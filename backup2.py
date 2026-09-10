import boto3
import json
import re
import logging
from datetime import timezone


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ============================================================
# AWS CLIENTS
# ============================================================

securityhub = boto3.client("securityhub")
ec2 = boto3.client("ec2")
cloudtrail = boto3.client("cloudtrail")


# ============================================================
# CONFIGURATION
# ============================================================

RULE_NAME = (
    "arn:aws-us-gov:config:us-gov-west-1:"
    "283388443887:config-rule/"
    "aws-service-rule/config-conforms.amazon.com/"
    "config-rule-lrI4h7"
)


# ============================================================
# ENVIRONMENT VPCS
# ============================================================

PROD_VPC = "vpc-26f4d42"

NONPROD_VPC = "vpc-c423b5a0"


# ============================================================
# RETENTION RULE
# ============================================================

PROD_MAX_DAYS = 14

NONPROD_MAX_DAYS = 7


# ============================================================
# DRY RUN
# ============================================================
#
# True:
#     Do NOT actually resolve Security Hub findings.
#     It will print what WOULD be resolved.
#
# False:
#     Actually resolve findings.
#
# ============================================================

DRY_RUN = True


# ============================================================
# DEFAULT TARGET
# ============================================================

DEFAULT_TARGET = 3000


# ============================================================
# LAMBDA HANDLER
# ============================================================

def lambda_handler(event, context):

    logger.info("")
    logger.info("====================================================")
    logger.info("AMI CREATION / DEREGISTRATION SECURITY HUB CHECK")
    logger.info("====================================================")

    logger.info(
        "DRY_RUN = %s",
        DRY_RUN
    )

    target = event.get(
        "target",
        DEFAULT_TARGET
    )

    logger.info(
        "Target findings = %s",
        target
    )

    findings = get_findings()

    logger.info(
        "Total matching findings retrieved = %s",
        len(findings)
    )

    processed = 0

    resolved = []

    non_compliant = []

    errors = []

    # ========================================================
    # PROCESS FINDINGS
    # ========================================================

    for finding in findings:

        if processed >= target:

            logger.info(
                "Reached target of %s findings.",
                target
            )

            break

        finding_id = finding.get(
            "Id",
            "UNKNOWN"
        )

        try:

            result = process_finding(
                finding
            )

            processed += 1

            if not result:
                continue

            if result.get(
                "status"
            ) == "RESOLVED":

                resolved.append(
                    result
                )

            elif result.get(
                "status"
            ) == "NON_COMPLIANT":

                non_compliant.append(
                    result
                )

            elif result.get(
                "status"
            ) == "ERROR":

                errors.append(
                    result
                )

        except Exception as e:

            processed += 1

            logger.exception(
                "Unexpected error processing finding %s",
                finding_id
            )

            errors.append({

                "status": "ERROR",

                "finding_id": finding_id,

                "reason": str(e)

            })

    # ========================================================
    # PRINT RESOLVED FINDINGS
    # ========================================================

    logger.info("")
    logger.info("====================================================")
    logger.info("RESOLVED FINDINGS")
    logger.info("====================================================")

    if not resolved:

        logger.info(
            "No findings were resolved."
        )

    else:

        for item in resolved:

            logger.info(
                "Finding=%s | AMI=%s | "
                "Environment=%s | "
                "AMI Lifetime=%s days | "
                "Limit=%s days | "
                "Action=%s",

                item.get("finding_id"),

                item.get("ami_id"),

                item.get("environment"),

                item.get("ami_age_days"),

                item.get("maximum_allowed_days"),

                item.get("action")
            )

    # ========================================================
    # PRINT NON-COMPLIANT FINDINGS
    # ========================================================

    logger.info("")
    logger.info("====================================================")
    logger.info("NON-COMPLIANT FINDINGS")
    logger.info("====================================================")

    if not non_compliant:

        logger.info(
            "No non-compliant findings."
        )

    else:

        for item in non_compliant:

            logger.warning(
                "Finding=%s | AMI=%s | "
                "Environment=%s | "
                "AMI Lifetime=%s days | "
                "Limit=%s days | "
                "Reason=%s",

                item.get("finding_id"),

                item.get("ami_id"),

                item.get("environment"),

                item.get("ami_age_days"),

                item.get("maximum_allowed_days"),

                item.get("reason")
            )

    # ========================================================
    # PRINT ERRORS
    # ========================================================

    logger.info("")
    logger.info("====================================================")
    logger.info("ERRORS")
    logger.info("====================================================")

    if not errors:

        logger.info(
            "No processing errors."
        )

    else:

        for item in errors:

            logger.error(
                "Finding=%s | Reason=%s",

                item.get("finding_id"),

                item.get("reason")
            )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    logger.info("")
    logger.info("====================================================")
    logger.info("FINAL SUMMARY")
    logger.info("====================================================")

    logger.info(
        "Target              : %s",
        target
    )

    logger.info(
        "Processed           : %s",
        processed
    )

    logger.info(
        "Resolved            : %s",
        len(resolved)
    )

    logger.info(
        "Non-Compliant       : %s",
        len(non_compliant)
    )

    logger.info(
        "Errors              : %s",
        len(errors)
    )

    logger.info(
        "DRY_RUN             : %s",
        DRY_RUN
    )

    logger.info(
        "===================================================="
    )

    return {

        "statusCode": 200,

        "target": target,

        "processed": processed,

        "resolved_count": len(
            resolved
        ),

        "non_compliant_count": len(
            non_compliant
        ),

        "error_count": len(
            errors
        ),

        "resolved": resolved,

        "non_compliant": non_compliant,

        "errors": errors
    }


# ============================================================
# GET SECURITY HUB FINDINGS
# ============================================================

def get_findings():

    findings = []

    next_token = None

    while True:

        params = {

            "Filters": {

                "GeneratorId": [

                    {
                        "Value": RULE_NAME,

                        "Comparison": "EQUALS"
                    }

                ],

                "WorkflowStatus": [

                    {
                        "Value": "NEW",

                        "Comparison": "EQUALS"
                    }

                ],

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

            params[
                "NextToken"
            ] = next_token

        response = securityhub.get_findings(
            **params
        )

        batch = response.get(
            "Findings",
            []
        )

        findings.extend(
            batch
        )

        logger.info(
            "Security Hub batch retrieved = %s | "
            "Total = %s",

            len(batch),

            len(findings)
        )

        next_token = response.get(
            "NextToken"
        )

        if not next_token:

            break

    return findings


# ============================================================
# EXTRACT AMI ID
# ============================================================

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
            "Resource Type=%s | Resource ID=%s",
            resource_type,
            resource_id
        )

        # ----------------------------------------------------
        # Direct AMI ID
        # ----------------------------------------------------

        if resource_id.startswith(
            "ami-"
        ):

            return resource_id

        # ----------------------------------------------------
        # Search AMI ID inside resource ID
        # ----------------------------------------------------

        match = re.search(
            r"(ami-[0-9a-fA-F]+)",
            resource_id
        )

        if match:

            return match.group(
                1
            )

        # ----------------------------------------------------
        # Resource details
        # ----------------------------------------------------

        details = resource.get(
            "Details",
            {}
        )

        backup_details = details.get(
            "AwsBackupRecoveryPoint",
            {}
        )

        backup_resource_arn = backup_details.get(
            "ResourceArn",
            ""
        )

        match = re.search(
            r"(ami-[0-9a-fA-F]+)",
            backup_resource_arn
        )

        if match:

            return match.group(
                1
            )

        # ----------------------------------------------------
        # Final fallback
        # ----------------------------------------------------

        try:

            resource_json = json.dumps(
                resource
            )

            match = re.search(
                r"(ami-[0-9a-fA-F]+)",
                resource_json
            )

            if match:

                return match.group(
                    1
                )

        except Exception:

            pass

    return None


# ============================================================
# GET AMI LIFECYCLE EVENTS FROM CLOUDTRAIL
# ============================================================

def get_ami_lifecycle_events(
    ami_id
):

    logger.info("")
    logger.info(
        "Searching CloudTrail for AMI: %s",
        ami_id
    )

    create_time = None

    deregister_time = None

    creator_instance_id = None

    next_token = None

    try:

        while True:

            params = {

                "LookupAttributes": [

                    {
                        "AttributeKey": "ResourceName",

                        "AttributeValue": ami_id
                    }

                ],

                "MaxResults": 50
            }

            if next_token:

                params[
                    "NextToken"
                ] = next_token

            response = cloudtrail.lookup_events(
                **params
            )

            events = response.get(
                "Events",
                []
            )

            logger.info(
                "CloudTrail events returned = %s",
                len(events)
            )

            for cloudtrail_event in events:

                event_name = cloudtrail_event.get(
                    "EventName"
                )

                event_time = cloudtrail_event.get(
                    "EventTime"
                )

                logger.info(
                    "CloudTrail Event=%s | Time=%s",
                    event_name,
                    event_time
                )

                # =================================================
                # CREATE IMAGE
                # =================================================

                if event_name == "CreateImage":

                    if event_time:

                        if (
                            create_time is None
                            or event_time < create_time
                        ):

                            create_time = event_time

                    try:

                        raw_event = cloudtrail_event.get(
                            "CloudTrailEvent",
                            "{}"
                        )

                        event_data = json.loads(
                            raw_event
                        )

                        request_parameters = event_data.get(
                            "requestParameters",
                            {}
                        )

                        instance_id = request_parameters.get(
                            "instanceId"
                        )

                        if instance_id:

                            creator_instance_id = (
                                instance_id
                            )

                            logger.info(
                                "AMI creator instance = %s",
                                instance_id
                            )

                    except Exception as e:

                        logger.warning(
                            "Unable to parse CreateImage "
                            "event for %s: %s",
                            ami_id,
                            str(e)
                        )

                # =================================================
                # DEREGISTER IMAGE
                # =================================================

                elif event_name == "DeregisterImage":

                    if event_time:

                        if (
                            deregister_time is None
                            or event_time > deregister_time
                        ):

                            deregister_time = event_time

            # ====================================================
            # PAGINATION
            # ====================================================

            next_token = response.get(
                "NextToken"
            )

            if not next_token:

                break

    except Exception as e:

        logger.error(
            "CloudTrail lookup failed for AMI %s: %s",
            ami_id,
            str(e)
        )

        return {

            "create_time": None,

            "deregister_time": None,

            "creator_instance_id": None
        }

    # ==========================================================
    # PRINT LIFECYCLE
    # ==========================================================

    logger.info("")
    logger.info(
        "---------------- AMI LIFECYCLE ----------------"
    )

    logger.info(
        "AMI ID           : %s",
        ami_id
    )

    logger.info(
        "CreateImage      : %s",
        create_time
    )

    logger.info(
        "DeregisterImage  : %s",
        deregister_time
    )

    logger.info(
        "Creator Instance : %s",
        creator_instance_id
    )

    logger.info(
        "-------------------------------------------------"
    )

    return {

        "create_time": create_time,

        "deregister_time": deregister_time,

        "creator_instance_id": creator_instance_id
    }


# ============================================================
# GET INSTANCE VPC
# ============================================================

def get_instance_vpc(
    instance_id
):

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

        instance = instances[0]

        vpc_id = instance.get(
            "VpcId"
        )

        logger.info(
            "Instance=%s | VPC=%s",
            instance_id,
            vpc_id
        )

        return vpc_id

    except ec2.exceptions.ClientError as e:

        error_code = e.response.get(
            "Error",
            {}
        ).get(
            "Code",
            ""
        )

        if error_code == (
            "InvalidInstanceID.NotFound"
        ):

            logger.warning(
                "Creator instance %s no longer exists.",
                instance_id
            )

            return "INSTANCE_NOT_FOUND"

        logger.error(
            "EC2 lookup failed for instance %s: %s",
            instance_id,
            str(e)
        )

        return None

    except Exception as e:

        logger.error(
            "Unable to determine VPC for %s: %s",
            instance_id,
            str(e)
        )

        return None


# ============================================================
# DETERMINE ENVIRONMENT
# ============================================================

def determine_environment(
    vpc_id
):

    if vpc_id == PROD_VPC:

        return "PROD"

    if vpc_id == NONPROD_VPC:

        return "NON-PROD"

    return None


# ============================================================
# CALCULATE AMI LIFETIME
# ============================================================

def calculate_ami_age_days(
    create_time,
    deregister_time
):

    if not create_time:

        return None

    if not deregister_time:

        return None

    if create_time.tzinfo is None:

        create_time = create_time.replace(
            tzinfo=timezone.utc
        )

    if deregister_time.tzinfo is None:

        deregister_time = deregister_time.replace(
            tzinfo=timezone.utc
        )

    seconds = (
        deregister_time - create_time
    ).total_seconds()

    if seconds < 0:

        return None

    return seconds / 86400


# ============================================================
# PROCESS ONE FINDING
# ============================================================

def process_finding(
    finding
):

    finding_id = finding.get(
        "Id"
    )

    product_arn = finding.get(
        "ProductArn"
    )

    logger.info("")
    logger.info("")
    logger.info(
        "===================================================="
    )

    logger.info(
        "PROCESSING FINDING"
    )

    logger.info(
        "Finding ID = %s",
        finding_id
    )

    logger.info(
        "===================================================="
    )

    # ========================================================
    # STEP 1 - EXTRACT AMI ID
    # ========================================================

    ami_id = extract_ami_id(
        finding
    )

    # ========================================================
    # NEW CONDITION:
    # AMI ID NOT FOUND -> RESOLVE
    # ========================================================

    if not ami_id:

        logger.warning(
            "AMI ID NOT FOUND."
        )

        logger.warning(
            "NEW RULE: AMI ID missing -> RESOLVE"
        )

        if DRY_RUN:

            logger.info(
                "DRY RUN: Finding WOULD be resolved."
            )

            action = "WOULD_RESOLVE"

        else:

            resolve_finding(
                product_arn=product_arn,
                finding_id=finding_id,
                ami_id="NOT_FOUND",
                environment="UNKNOWN",
                ami_age_days=None,
                reason="AMI ID not found"
            )

            action = "RESOLVED"

        return {

            "status": "RESOLVED",

            "finding_id": finding_id,

            "ami_id": None,

            "environment": "UNKNOWN",

            "ami_age_days": None,

            "maximum_allowed_days": None,

            "action": action,

            "reason": (
                "AMI ID not found - "
                "resolved according to new rule"
            )
        }

    logger.info(
        "AMI ID = %s",
        ami_id
    )

    # ========================================================
    # STEP 2 - CLOUDTRAIL
    # ========================================================

    lifecycle = get_ami_lifecycle_events(
        ami_id
    )

    create_time = lifecycle.get(
        "create_time"
    )

    deregister_time = lifecycle.get(
        "deregister_time"
    )

    creator_instance_id = lifecycle.get(
        "creator_instance_id"
    )

    # ========================================================
    # NEW CONDITION:
    # INSTANCE ID NOT FOUND -> RESOLVE
    # ========================================================

    if not creator_instance_id:

        logger.warning(
            "Creator INSTANCE ID NOT FOUND."
        )

        logger.warning(
            "NEW RULE: Instance ID missing -> RESOLVE"
        )

        if DRY_RUN:

            logger.info(
                "DRY RUN: Finding WOULD be resolved."
            )

            action = "WOULD_RESOLVE"

        else:

            resolve_finding(
                product_arn=product_arn,
                finding_id=finding_id,
                ami_id=ami_id,
                environment="UNKNOWN",
                ami_age_days=None,
                reason="Creator instance ID not found"
            )

            action = "RESOLVED"

        return {

            "status": "RESOLVED",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "ami_age_days": None,

            "maximum_allowed_days": None,

            "action": action,

            "reason": (
                "Creator instance ID not found - "
                "resolved according to new rule"
            )
        }

    # ========================================================
    # CREATE IMAGE NOT FOUND
    # ========================================================

    if not create_time:

        logger.warning(
            "CreateImage event NOT FOUND."
        )

        logger.warning(
            "RESULT = NON-COMPLIANT"
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "reason": (
                "CreateImage CloudTrail event "
                "was not found"
            )
        }

    # ========================================================
    # DEREGISTER IMAGE NOT FOUND
    # ========================================================

    if not deregister_time:

        logger.warning(
            "DeregisterImage event NOT FOUND."
        )

        logger.warning(
            "RESULT = NON-COMPLIANT"
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "reason": (
                "DeregisterImage CloudTrail event "
                "was not found"
            )
        }

    # ========================================================
    # STEP 3 - GET VPC
    # ========================================================

    vpc_id = get_instance_vpc(
        creator_instance_id
    )

    # ========================================================
    # INSTANCE NO LONGER EXISTS
    # ========================================================

    if vpc_id == "INSTANCE_NOT_FOUND":

        logger.warning(
            "Creator instance no longer exists."
        )

        logger.warning(
            "NEW RULE: Instance not found -> RESOLVE"
        )

        if DRY_RUN:

            logger.info(
                "DRY RUN: Finding WOULD be resolved."
            )

            action = "WOULD_RESOLVE"

        else:

            resolve_finding(
                product_arn=product_arn,
                finding_id=finding_id,
                ami_id=ami_id,
                environment="UNKNOWN",
                ami_age_days=None,
                reason="Creator instance no longer exists"
            )

            action = "RESOLVED"

        return {

            "status": "RESOLVED",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "ami_age_days": None,

            "maximum_allowed_days": None,

            "action": action,

            "reason": (
                "Creator instance no longer exists - "
                "resolved according to new rule"
            )
        }

    # ========================================================
    # VPC NOT FOUND
    # ========================================================

    if not vpc_id:

        logger.warning(
            "VPC could not be determined."
        )

        logger.warning(
            "RESULT = NON-COMPLIANT"
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "reason": (
                "Could not determine creator "
                "instance VPC"
            )
        }

    # ========================================================
    # STEP 4 - DETERMINE ENVIRONMENT
    # ========================================================

    environment = determine_environment(
        vpc_id
    )

    if not environment:

        logger.warning(
            "VPC %s is not configured as "
            "PROD or NON-PROD.",
            vpc_id
        )

        logger.warning(
            "RESULT = NON-COMPLIANT"
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": "UNKNOWN",

            "vpc_id": vpc_id,

            "reason": (
                "VPC does not match configured "
                "PROD or NON-PROD VPC"
            )
        }

    logger.info(
        "Environment = %s",
        environment
    )

    # ========================================================
    # STEP 5 - DETERMINE LIMIT
    # ========================================================

    if environment == "PROD":

        maximum_allowed_days = (
            PROD_MAX_DAYS
        )

    else:

        maximum_allowed_days = (
            NONPROD_MAX_DAYS
        )

    # ========================================================
    # STEP 6 - CALCULATE AMI LIFETIME
    # ========================================================

    ami_age_days = calculate_ami_age_days(

        create_time,

        deregister_time
    )

    if ami_age_days is None:

        logger.warning(
            "Unable to calculate AMI lifetime."
        )

        logger.warning(
            "RESULT = NON-COMPLIANT"
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": environment,

            "reason": (
                "Unable to calculate AMI "
                "creation-to-deregistration duration"
            )
        }

    # ========================================================
    # PRINT COMPLETE CHECK
    # ========================================================

    logger.info("")
    logger.info(
        "---------------- COMPLIANCE CHECK ----------------"
    )

    logger.info(
        "Finding ID          : %s",
        finding_id
    )

    logger.info(
        "AMI ID              : %s",
        ami_id
    )

    logger.info(
        "Creator Instance    : %s",
        creator_instance_id
    )

    logger.info(
        "VPC                 : %s",
        vpc_id
    )

    logger.info(
        "Environment         : %s",
        environment
    )

    logger.info(
        "AMI Created         : %s",
        create_time
    )

    logger.info(
        "AMI Deregistered    : %s",
        deregister_time
    )

    logger.info(
        "AMI Lifetime        : %.4f days",
        ami_age_days
    )

    logger.info(
        "Required Minimum    : %s days",
        maximum_allowed_days
    )

    logger.info(
        "----------------------------------------------------"
    )

    # ========================================================
    # NEW RULE
    #
    # PROD:
    #     >= 14 DAYS -> RESOLVE
    #     <  14 DAYS -> NON-COMPLIANT
    #
    # NON-PROD:
    #     >= 7 DAYS -> RESOLVE
    #     <  7 DAYS -> NON-COMPLIANT
    # ========================================================

    if ami_age_days >= maximum_allowed_days:

        # ====================================================
        # RESOLVE
        # ====================================================

        logger.info(
            "RESULT              : RESOLVED"
        )

        logger.info(
            "REASON              : AMI lifetime "
            "is greater than or equal to "
            "required threshold."
        )

        if DRY_RUN:

            logger.info(
                "DRY RUN             : YES"
            )

            logger.info(
                "Security Hub finding WOULD be resolved."
            )

            action = "WOULD_RESOLVE"

        else:

            logger.info(
                "DRY RUN             : NO"
            )

            resolve_finding(

                product_arn=product_arn,

                finding_id=finding_id,

                ami_id=ami_id,

                environment=environment,

                ami_age_days=ami_age_days,

                reason=(
                    "AMI lifetime is greater than "
                    "or equal to required threshold"
                )
            )

            action = "RESOLVED"

        return {

            "status": "RESOLVED",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": environment,

            "vpc_id": vpc_id,

            "ami_created": (
                create_time.isoformat()
            ),

            "ami_deregistered": (
                deregister_time.isoformat()
            ),

            "ami_age_days": round(
                ami_age_days,
                4
            ),

            "maximum_allowed_days": (
                maximum_allowed_days
            ),

            "action": action,

            "reason": (
                "AMI lifetime >= required threshold"
            )
        }

    # ========================================================
    # NON-COMPLIANT
    # ========================================================

    else:

        logger.warning(
            "RESULT              : NON-COMPLIANT"
        )

        logger.warning(
            "REASON              : AMI lifetime "
            "is LESS than required threshold."
        )

        logger.warning(
            "AMI lifetime = %.4f days | "
            "Required = %s days",
            ami_age_days,
            maximum_allowed_days
        )

        return {

            "status": "NON_COMPLIANT",

            "finding_id": finding_id,

            "ami_id": ami_id,

            "environment": environment,

            "vpc_id": vpc_id,

            "ami_created": (
                create_time.isoformat()
            ),

            "ami_deregistered": (
                deregister_time.isoformat()
            ),

            "ami_age_days": round(
                ami_age_days,
                4
            ),

            "maximum_allowed_days": (
                maximum_allowed_days
            ),

            "reason": (
                "AMI lifetime is less than "
                "required threshold"
            )
        }


# ============================================================
# RESOLVE SECURITY HUB FINDING
# ============================================================

def resolve_finding(
    product_arn,
    finding_id,
    ami_id,
    environment,
    ami_age_days,
    reason
):

    if ami_age_days is not None:

        age_text = (
            f"{ami_age_days:.4f} days"
        )

    else:

        age_text = "N/A"

    message = (

        f"Security Hub finding automatically resolved. "

        f"AMI={ami_id}. "

        f"Environment={environment}. "

        f"AMI lifetime={age_text}. "

        f"Reason={reason}. "

        f"Updated by AMI-Retention-AutoResolver."
    )

    logger.info("")
    logger.info(
        "Resolving Security Hub finding..."
    )

    logger.info(
        "Finding ID = %s",
        finding_id
    )

    try:

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

                "UpdatedBy": (
                    "AMI-Retention-AutoResolver"
                )
            }
        )

        logger.info(
            "Security Hub update successful."
        )

        logger.info(
            "Finding %s RESOLVED.",
            finding_id
        )

        return response

    except Exception as e:

        logger.error(
            "FAILED to resolve finding %s: %s",
            finding_id,
            str(e)
        )

        raise
