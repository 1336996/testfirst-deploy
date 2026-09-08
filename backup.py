import boto3
import json
import re
import logging
from datetime import datetime, timezone


# =========================================================
# Logging
# =========================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# =========================================================
# AWS Clients
# =========================================================

securityhub = boto3.client("securityhub")
ec2 = boto3.client("ec2")
cloudtrail = boto3.client("cloudtrail")
backup = boto3.client("backup")


# =========================================================
# Configuration
# =========================================================

RULE_NAME = (
    "arn:aws-us-gov:config:us-gov-west-1:"
    "283388443887:config-rule/"
    "aws-service-rule/config-conforms.amazon.com/config-rule-lrI4h7"
)

PROD_VPC = "vpc-26f4d42"
NONPROD_VPC = "vpc-c423b5a0"

# Backup requirements
PROD_MAX_DAYS = 7
NONPROD_MAX_DAYS = 14

# ---------------------------------------------------------
# IMPORTANT:
#
# Set to True for the first test.
#
# True  = Lambda will NOT resolve Security Hub findings.
# False = Lambda WILL resolve compliant findings.
# ---------------------------------------------------------

DRY_RUN = True


# =========================================================
# Lambda Handler
# =========================================================

def lambda_handler(event, context):

    logger.info("==========================================")
    logger.info("AMI Backup Security Hub Remediation")
    logger.info("==========================================")

    logger.info("DRY_RUN = %s", DRY_RUN)

    target = event.get("target", 500)

    findings = get_findings()

    logger.info(
        "Found %s Security Hub findings",
        len(findings)
    )

    processed = 0
    resolved = []
    non_compliant = []

    for finding in findings:

        if processed >= target:
            logger.info(
                "Reached target of %s findings",
                target
            )
            break

        result = process_finding(finding)

        processed += 1

        if result:

            if result["status"] == "RESOLVED":
                resolved.append(result)

            elif result["status"] == "NON_COMPLIANT":
                non_compliant.append(result)

    # =====================================================
    # Print NON-COMPLIANT list
    # =====================================================

    logger.info("")
    logger.info("==========================================")
    logger.info("NON-COMPLIANT AMIs")
    logger.info("==========================================")

    if not non_compliant:

        logger.info("No non-compliant AMIs.")

    else:

        for item in non_compliant:

            logger.info(
                "AMI=%s | Environment=%s | "
                "BackupAge=%s days | "
                "MaximumAllowed=%s days | "
                "Finding=%s | Reason=%s",
                item.get("ami_id"),
                item.get("environment"),
                item.get("backup_age_days"),
                item.get("maximum_allowed_days"),
                item.get("finding_id"),
                item.get("reason")
            )

    # =====================================================
    # Print RESOLVED list
    # =====================================================

    logger.info("")
    logger.info("==========================================")
    logger.info("RESOLVED FINDINGS")
    logger.info("==========================================")

    if not resolved:

        logger.info("No findings resolved.")

    else:

        for item in resolved:

            logger.info(
                "AMI=%s | Environment=%s | "
                "BackupAge=%s days | Finding=%s",
                item.get("ami_id"),
                item.get("environment"),
                item.get("backup_age_days"),
                item.get("finding_id")
            )

    # =====================================================
    # Summary
    # =====================================================

    logger.info("")
    logger.info("==========================================")
    logger.info(
        "Processed       : %s",
        processed
    )
    logger.info(
        "Resolved        : %s",
        len(resolved)
    )
    logger.info(
        "Non-Compliant   : %s",
        len(non_compliant)
    )
    logger.info("==========================================")

    return {
        "statusCode": 200,
        "processed": processed,
        "resolved_count": len(resolved),
        "non_compliant_count": len(non_compliant),
        "resolved": resolved,
        "non_compliant": non_compliant
    }


# =========================================================
# Get Security Hub Findings
# =========================================================

def get_findings():

    findings = []
    next_token = None

    while True:

        params = {
            "Filters": {

                # Your specific AWS Config rule
                "GeneratorId": [
                    {
                        "Value": RULE_NAME,
                        "Comparison": "EQUALS"
                    }
                ],

                # Only NEW findings
                "WorkflowStatus": [
                    {
                        "Value": "NEW",
                        "Comparison": "EQUALS"
                    }
                ],

                # Only active findings
                "RecordState": [
                    {
                        "Value": "ACTIVE",
                        "Comparison": "EQUALS"
                    }
                ]
            },

            "MaxResults": 100
        }

        if next_token:

            params["NextToken"] = next_token

        response = securityhub.get_findings(
            **params
        )

        batch = response.get(
            "Findings",
            []
        )

        findings.extend(batch)

        logger.info(
            "Fetched %s findings. Total=%s",
            len(batch),
            len(findings)
        )

        next_token = response.get(
            "NextToken"
        )

        if not next_token:
            break

    return findings


# =========================================================
# Extract AMI ID
# =========================================================

def extract_ami_id(finding):

    resources = finding.get(
        "Resources",
        []
    )

    for resource in resources:

        resource_id = resource.get(
            "Id",
            ""
        )

        resource_type = resource.get(
            "Type",
            ""
        )

        logger.info(
            "Security Hub resource type=%s id=%s",
            resource_type,
            resource_id
        )

        # -------------------------------------------------
        # Direct AMI ID
        # -------------------------------------------------

        if resource_id.startswith("ami-"):

            return resource_id

        # -------------------------------------------------
        # AMI ARN
        #
        # Example:
        # arn:aws-us-gov:ec2:us-gov-west-1::image/ami-123456
        # -------------------------------------------------

        match = re.search(
            r"(ami-[0-9a-fA-F]+)",
            resource_id
        )

        if match:

            return match.group(1)

        # -------------------------------------------------
        # Check AwsBackupRecoveryPoint details
        # -------------------------------------------------

        details = resource.get(
            "Details",
            {}
        )

        backup_details = details.get(
            "AwsBackupRecoveryPoint",
            {}
        )

        resource_arn = backup_details.get(
            "ResourceArn",
            ""
        )

        match = re.search(
            r"(ami-[0-9a-fA-F]+)",
            resource_arn
        )

        if match:

            return match.group(1)

    return None


# =========================================================
# Find EC2 Instance That Created AMI
# =========================================================

def find_creator_instance(ami_id):

    logger.info(
        "Searching CloudTrail for CreateImage event: %s",
        ami_id
    )

    try:

        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    "AttributeKey": "ResourceName",
                    "AttributeValue": ami_id
                }
            ],
            MaxResults=50
        )

    except Exception as e:

        logger.error(
            "CloudTrail lookup failed for %s: %s",
            ami_id,
            str(e)
        )

        return None

    events = response.get(
        "Events",
        []
    )

    logger.info(
        "CloudTrail returned %s events for %s",
        len(events),
        ami_id
    )

    for event in events:

        if event.get("EventName") != "CreateImage":
            continue

        try:

            cloudtrail_event = event.get(
                "CloudTrailEvent",
                "{}"
            )

            data = json.loads(
                cloudtrail_event
            )

            request_parameters = data.get(
                "requestParameters",
                {}
            )

            instance_id = request_parameters.get(
                "instanceId"
            )

            if instance_id:

                logger.info(
                    "AMI %s was created from instance %s",
                    ami_id,
                    instance_id
                )

                return instance_id

        except Exception as e:

            logger.warning(
                "Unable to parse CloudTrail event "
                "for AMI %s: %s",
                ami_id,
                str(e)
            )

    logger.warning(
        "No CreateImage CloudTrail event found for %s",
        ami_id
    )

    return None


# =========================================================
# Get Instance VPC
# =========================================================

def get_instance_vpc(instance_id):

    try:

        response = ec2.describe_instances(
            InstanceIds=[
                instance_id
            ]
        )

        reservations = response.get(
            "Reservations",
            []
        )

        if not reservations:
            return None

        instances = reservations[0].get(
            "Instances",
            []
        )

        if not instances:
            return None

        vpc_id = instances[0].get(
            "VpcId"
        )

        logger.info(
            "Instance %s belongs to VPC %s",
            instance_id,
            vpc_id
        )

        return vpc_id

    except Exception as e:

        logger.error(
            "Unable to get VPC for instance %s: %s",
            instance_id,
            str(e)
        )

        return None


# =========================================================
# Determine PROD / NON-PROD
# =========================================================

def determine_environment(vpc_id):

    if vpc_id == PROD_VPC:

        return "PROD"

    if vpc_id == NONPROD_VPC:

        return "NON-PROD"

    return None


# =========================================================
# Get Last Backup Time
# =========================================================

def get_last_backup_time(ami_id):

    region = boto3.session.Session().region_name

    if not region:

        logger.error(
            "Lambda AWS region could not be determined"
        )

        return None

    # -----------------------------------------------------
    # AWS partition
    #
    # GovCloud:
    # aws-us-gov
    #
    # Standard AWS:
    # aws
    # -----------------------------------------------------

    session = boto3.session.Session()

    partition = session.get_partition_for_region(
        region
    )

    # -----------------------------------------------------
    # AWS Backup EC2 AMI resource ARN
    #
    # Example:
    #
    # arn:aws-us-gov:ec2:us-gov-west-1::image/ami-xxxx
    # -----------------------------------------------------

    resource_arn = (
        f"arn:{partition}:ec2:"
        f"{region}::image/{ami_id}"
    )

    logger.info(
        "AWS Backup resource ARN: %s",
        resource_arn
    )

    try:

        response = backup.describe_protected_resource(
            ResourceArn=resource_arn
        )

        last_backup_time = response.get(
            "LastBackupTime"
        )

        if last_backup_time is None:

            logger.warning(
                "No LastBackupTime returned for %s",
                ami_id
            )

            return None

        # -------------------------------------------------
        # AWS returns LastBackupTime as Unix timestamp
        # -------------------------------------------------

        backup_datetime = datetime.fromtimestamp(
            float(last_backup_time),
            tz=timezone.utc
        )

        logger.info(
            "AMI %s last backup: %s",
            ami_id,
            backup_datetime.isoformat()
        )

        return backup_datetime

    except backup.exceptions.ResourceNotFoundException:

        logger.warning(
            "AMI %s is not found as a protected "
            "AWS Backup resource",
            ami_id
        )

        return None

    except Exception as e:

        logger.error(
            "AWS Backup lookup failed for %s: %s",
            ami_id,
            str(e)
        )

        return None


# =========================================================
# Calculate Backup Age
# =========================================================

def calculate_backup_age_days(
    last_backup_time
):

    if last_backup_time is None:

        return None

    now = datetime.now(
        timezone.utc
    )

    age_seconds = (
        now - last_backup_time
    ).total_seconds()

    return age_seconds / 86400


# =========================================================
# Process Finding
# =========================================================

def process_finding(finding):

    finding_id = finding.get(
        "Id"
    )

    product_arn = finding.get(
        "ProductArn"
    )

    logger.info("")
    logger.info("==========================================")
    logger.info(
        "Processing finding: %s",
        finding_id
    )
    logger.info("==========================================")


    # =====================================================
    # 1. Extract AMI
    # =====================================================

    ami_id = extract_ami_id(
        finding
    )

    if not ami_id:

        logger.warning(
            "AMI ID not found for finding %s",
            finding_id
        )

        return {
            "status": "NON_COMPLIANT",
            "finding_id": finding_id,
            "ami_id": None,
            "environment": "UNKNOWN",
            "reason": "AMI ID could not be extracted"
        }

    logger.info(
        "AMI ID = %s",
        ami_id
    )


    # =====================================================
    # 2. Find creator EC2 instance
    # =====================================================

    instance_id = find_creator_instance(
        ami_id
    )

    if not instance_id:

        return {
            "status": "NON_COMPLIANT",
            "finding_id": finding_id,
            "ami_id": ami_id,
            "environment": "UNKNOWN",
            "reason": "Could not find AMI creator instance"
        }


    # =====================================================
    # 3. Get VPC
    # =====================================================

    vpc_id = get_instance_vpc(
        instance_id
    )

    if not vpc_id:

        return {
            "status": "NON_COMPLIANT",
            "finding_id": finding_id,
            "ami_id": ami_id,
            "environment": "UNKNOWN",
            "reason": "Could not determine VPC"
        }


    # =====================================================
    # 4. Determine environment
    # =====================================================

    environment = determine_environment(
        vpc_id
    )

    if not environment:

        logger.warning(
            "VPC %s is neither PROD nor NON-PROD",
            vpc_id
        )

        return {
            "status": "NON_COMPLIANT",
            "finding_id": finding_id,
            "ami_id": ami_id,
            "environment": "UNKNOWN",
            "vpc_id": vpc_id,
            "reason": "VPC does not match configured PROD/NON-PROD VPC"
        }


    logger.info(
        "Environment = %s",
        environment
    )


    # =====================================================
    # 5. Get latest backup
    # =====================================================

    last_backup_time = get_last_backup_time(
        ami_id
    )

    # Maximum allowed age
    if environment == "PROD":

        max_allowed_days = PROD_MAX_DAYS

    else:

        max_allowed_days = NONPROD_MAX_DAYS


    # =====================================================
    # 6. No backup found
    # =====================================================

    if last_backup_time is None:

        logger.warning(
            "No backup found for AMI %s",
            ami_id
        )

        return {
            "status": "NON_COMPLIANT",
            "finding_id": finding_id,
            "ami_id": ami_id,
            "environment": environment,
            "backup_age_days": None,
            "maximum_allowed_days": max_allowed_days,
            "reason": "No AWS Backup found"
        }


    # =====================================================
    # 7. Calculate backup age
    # =====================================================

    backup_age_days = calculate_backup_age_days(
        last_backup_time
    )

    logger.info(
        "Backup age = %.2f days",
        backup_age_days
    )

    logger.info(
        "Maximum allowed = %s days",
        max_allowed_days
    )


    # =====================================================
    # 8. Compliance check
    # =====================================================

    if backup_age_days <= max_allowed_days:

        logger.info(
            "COMPLIANT"
        )

        logger.info(
            "AMI %s has backup within allowed period",
            ami_id
        )


        # -------------------------------------------------
        # Resolve Security Hub finding
        # -------------------------------------------------

        if DRY_RUN:

            logger.info(
                "DRY_RUN=True - finding would be RESOLVED"
            )

        else:

            resolve_finding(
                product_arn=product_arn,
                finding_id=finding_id,
                ami_id=ami_id,
                environment=environment,
                backup_age_days=backup_age_days
            )


        return {
            "status": "RESOLVED",
            "finding_id": finding_id,
            "ami_id": ami_id,
            "environment": environment,
            "backup_age_days": round(
                backup_age_days,
                2
            )
        }


    # =====================================================
    # 9. NON-COMPLIANT
    # =====================================================

    logger.warning(
        "NON-COMPLIANT"
    )

    logger.warning(
        "AMI %s backup is %.2f days old. "
        "Maximum allowed = %s days",
        ami_id,
        backup_age_days,
        max_allowed_days
    )

    return {
        "status": "NON_COMPLIANT",
        "finding_id": finding_id,
        "ami_id": ami_id,
        "environment": environment,
        "backup_age_days": round(
            backup_age_days,
            2
        ),
        "maximum_allowed_days": max_allowed_days,
        "reason": "Latest backup is older than allowed"
    }


# =========================================================
# Resolve Security Hub Finding
# =========================================================

def resolve_finding(
    product_arn,
    finding_id,
    ami_id,
    environment,
    backup_age_days
):

    message = (
        f"AMI {ami_id} is compliant with the backup "
        f"requirement. Environment={environment}. "
        f"Latest backup age={backup_age_days:.2f} days."
    )

    logger.info(
        "Resolving Security Hub finding %s",
        finding_id
    )

    response = securityhub.batch_update_findings(

        FindingIdentifiers=[
            {
                "ProductArn": product_arn,
                "Id": finding_id
            }
        ],

        Workflow={
            "Status": "RESOLVED"
        },

        Note={
            "Text": message,
            "UpdatedBy": "AMI-Retention-AutoResolver"
        }
    )

    logger.info(
        "Security Hub update response: %s",
        response
    )

    logger.info(
        "Finding %s successfully resolved",
        finding_id
    )
webex. Press tab to insert.
