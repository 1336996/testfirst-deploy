import boto3
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
backup = boto3.client("backup")


# =========================================================
# Configuration
# =========================================================

PROD_MAX_DAYS = 7
NON_PROD_MAX_DAYS = 14

# Security Hub finding title keyword
BACKUP_KEYWORD = "backup"


# =========================================================
# Lambda Handler
# =========================================================

def lambda_handler(event, context):

    logger.info("Starting Security Hub backup compliance check")

    non_compliant = []
    resolved = []

    # -----------------------------------------------------
    # Get Security Hub findings
    # -----------------------------------------------------

    findings = get_backup_findings()

    logger.info(
        "Found %s backup-related Security Hub findings",
        len(findings)
    )

    # -----------------------------------------------------
    # Process every finding
    # -----------------------------------------------------

    for finding in findings:

        try:

            finding_id = finding["Id"]
            product_arn = finding["ProductArn"]

            logger.info("")
            logger.info(
                "Processing finding: %s",
                finding_id
            )

            # =================================================
            # 1. Extract AMI ID
            # =================================================

            ami_id = extract_ami_id(finding)

            # -------------------------------------------------
            # IMPORTANT CHANGE:
            #
            # If AMI ID cannot be extracted, resolve/archive
            # the Security Hub finding.
            # -------------------------------------------------

            if not ami_id:

                logger.warning(
                    "AMI ID not found in finding %s",
                    finding_id
                )

                logger.warning(
                    "Resolving and archiving finding because "
                    "AMI ID does not exist in the finding."
                )

                resolve_security_hub_finding(
                    finding_id=finding_id,
                    product_arn=product_arn,
                    ami_id="AMI-NOT-FOUND",
                    backup_age_days=None,
                    reason="AMI ID not present in Security Hub finding"
                )

                resolved.append({
                    "finding_id": finding_id,
                    "ami_id": None,
                    "environment": "UNKNOWN",
                    "reason": "AMI ID not present in finding"
                })

                continue

            logger.info(
                "AMI ID: %s",
                ami_id
            )

            # =================================================
            # 2. Determine PROD / NON-PROD
            # =================================================

            environment = get_ami_environment(
                ami_id
            )

            # -------------------------------------------------
            # IMPORTANT CHANGE:
            #
            # If AMI ID exists in Security Hub but the actual
            # AMI no longer exists in EC2, resolve/archive.
            # -------------------------------------------------

            if environment == "AMI_NOT_FOUND":

                logger.warning(
                    "AMI %s no longer exists.",
                    ami_id
                )

                logger.warning(
                    "Resolving and archiving Security Hub finding."
                )

                resolve_security_hub_finding(
                    finding_id=finding_id,
                    product_arn=product_arn,
                    ami_id=ami_id,
                    backup_age_days=None,
                    reason="AMI no longer exists"
                )

                resolved.append({
                    "finding_id": finding_id,
                    "ami_id": ami_id,
                    "environment": "NOT_FOUND",
                    "reason": "AMI no longer exists"
                })

                continue

            # -------------------------------------------------
            # Environment cannot be determined
            # -------------------------------------------------

            if not environment:

                logger.warning(
                    "Could not determine environment for AMI %s",
                    ami_id
                )

                non_compliant.append({
                    "finding_id": finding_id,
                    "ami_id": ami_id,
                    "environment": "UNKNOWN",
                    "reason": "Environment tag not found"
                })

                continue

            logger.info(
                "AMI %s environment: %s",
                ami_id,
                environment
            )

            # =================================================
            # 3. Get latest backup
            # =================================================

            latest_backup = get_latest_backup(
                ami_id
            )

            if not latest_backup:

                logger.warning(
                    "No AWS Backup recovery point found for %s",
                    ami_id
                )

                non_compliant.append({
                    "finding_id": finding_id,
                    "ami_id": ami_id,
                    "environment": environment,
                    "reason": "No backup found"
                })

                continue

            # =================================================
            # 4. Calculate backup age
            # =================================================

            backup_age_days = calculate_backup_age(
                latest_backup
            )

            logger.info(
                "AMI %s latest backup age: %.2f days",
                ami_id,
                backup_age_days
            )

            # =================================================
            # 5. Determine allowed backup age
            # =================================================

            if environment.lower() == "prod":

                max_days = PROD_MAX_DAYS

            else:

                max_days = NON_PROD_MAX_DAYS

            logger.info(
                "AMI %s maximum allowed backup age: %s days",
                ami_id,
                max_days
            )

            # =================================================
            # 6. Compliance check
            # =================================================

            if backup_age_days <= max_days:

                logger.info(
                    "AMI %s is COMPLIANT. "
                    "Backup age %.2f days <= %s days",
                    ami_id,
                    backup_age_days,
                    max_days
                )

                # -------------------------------------------------
                # Resolve + Archive
                # -------------------------------------------------

                resolve_security_hub_finding(
                    finding_id=finding_id,
                    product_arn=product_arn,
                    ami_id=ami_id,
                    backup_age_days=backup_age_days,
                    reason=(
                        f"{environment.upper()} AMI backup is "
                        f"within the allowed {max_days}-day period"
                    )
                )

                resolved.append({
                    "finding_id": finding_id,
                    "ami_id": ami_id,
                    "environment": environment,
                    "backup_age_days": round(
                        backup_age_days,
                        2
                    ),
                    "maximum_allowed_days": max_days,
                    "reason": "Backup is within allowed period"
                })

            else:

                logger.warning(
                    "AMI %s is NON-COMPLIANT. "
                    "Backup age %.2f days > %s days",
                    ami_id,
                    backup_age_days,
                    max_days
                )

                # -------------------------------------------------
                # Do NOT resolve
                # -------------------------------------------------

                non_compliant.append({
                    "finding_id": finding_id,
                    "ami_id": ami_id,
                    "environment": environment,
                    "backup_age_days": round(
                        backup_age_days,
                        2
                    ),
                    "maximum_allowed_days": max_days,
                    "reason": "Backup is older than allowed"
                })

        except Exception as e:

            logger.exception(
                "Error processing finding %s: %s",
                finding.get("Id"),
                str(e)
            )

            non_compliant.append({
                "finding_id": finding.get("Id"),
                "reason": str(e)
            })

    # =========================================================
    # Final Non-Compliant List
    # =========================================================

    logger.info("")
    logger.info("========================================")
    logger.info("NON-COMPLIANT AMIs")
    logger.info("========================================")

    for item in non_compliant:

        logger.info(
            "%s",
            item
        )

    # =========================================================
    # Resolved List
    # =========================================================

    logger.info("")
    logger.info("========================================")
    logger.info("RESOLVED FINDINGS")
    logger.info("========================================")

    for item in resolved:

        logger.info(
            "%s",
            item
        )

    # =========================================================
    # Summary
    # =========================================================

    logger.info("")
    logger.info("========================================")
    logger.info("FINAL SUMMARY")
    logger.info("========================================")

    logger.info(
        "Total Findings     = %s",
        len(findings)
    )

    logger.info(
        "Resolved            = %s",
        len(resolved)
    )

    logger.info(
        "Non-Compliant       = %s",
        len(non_compliant)
    )

    logger.info("========================================")

    return {
        "statusCode": 200,

        "total_findings": len(findings),

        "resolved_count": len(resolved),

        "non_compliant_count": len(non_compliant),

        "non_compliant": non_compliant,

        "resolved": resolved
    }


# =========================================================
# Security Hub - Get Findings
# =========================================================

def get_backup_findings():

    findings = []

    paginator = securityhub.get_paginator(
        "get_findings"
    )

    # -----------------------------------------------------
    # Filters
    # -----------------------------------------------------

    filters = {

        "WorkflowStatus": [
            {
                "Value": "NEW",
                "Comparison": "EQUALS"
            }
        ],

        "Title": [
            {
                "Value": BACKUP_KEYWORD,
                "Comparison": "CONTAINS"
            }
        ]
    }

    # -----------------------------------------------------
    # Get ALL pages
    # -----------------------------------------------------

    for page in paginator.paginate(
        Filters=filters
    ):

        page_findings = page.get(
            "Findings",
            []
        )

        findings.extend(
            page_findings
        )

        logger.info(
            "Retrieved %s findings. Total so far: %s",
            len(page_findings),
            len(findings)
        )

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

        logger.info(
            "Security Hub resource ID: %s",
            resource_id
        )

        # -------------------------------------------------
        # Direct AMI ID
        #
        # Example:
        # ami-0123456789abcdef
        # -------------------------------------------------

        if resource_id.startswith("ami-"):

            return resource_id

        # -------------------------------------------------
        # AMI ARN
        #
        # Example:
        # arn:aws:ec2:us-east-1:123456789012:image/ami-xxxx
        # -------------------------------------------------

        if ":image/ami-" in resource_id:

            return resource_id.split(
                ":image/"
            )[-1]

    # -----------------------------------------------------
    # AMI ID not present
    # -----------------------------------------------------

    return None


# =========================================================
# Get AMI Environment
# =========================================================

def get_ami_environment(ami_id):

    try:

        response = ec2.describe_images(
            ImageIds=[
                ami_id
            ]
        )

        images = response.get(
            "Images",
            []
        )

        # -------------------------------------------------
        # AMI does not exist
        # -------------------------------------------------

        if not images:

            logger.warning(
                "AMI %s does not exist.",
                ami_id
            )

            return "AMI_NOT_FOUND"

        image = images[0]

        tags = image.get(
            "Tags",
            []
        )

        # -------------------------------------------------
        # Find Environment / Env tag
        # -------------------------------------------------

        for tag in tags:

            key = tag.get(
                "Key",
                ""
            ).lower()

            value = tag.get(
                "Value",
                ""
            ).lower()

            if key in [
                "environment",
                "env"
            ]:

                if value in [
                    "prod",
                    "production"
                ]:

                    return "prod"

                return "non-prod"

        # -------------------------------------------------
        # AMI exists but Environment tag missing
        # -------------------------------------------------

        return None

    except Exception as e:

        error_message = str(e)

        # -------------------------------------------------
        # IMPORTANT:
        #
        # EC2 normally returns an InvalidAMIID.NotFound
        # error when the AMI no longer exists.
        # -------------------------------------------------

        if (
            "InvalidAMIID.NotFound" in error_message
            or "does not exist" in error_message.lower()
            or "not exist" in error_message.lower()
        ):

            logger.warning(
                "AMI %s no longer exists: %s",
                ami_id,
                error_message
            )

            return "AMI_NOT_FOUND"

        # -------------------------------------------------
        # Other EC2 errors should NOT cause automatic
        # resolution.
        # -------------------------------------------------

        logger.error(
            "Unable to determine environment for AMI %s: %s",
            ami_id,
            error_message
        )

        return None


# =========================================================
# Get Latest AWS Backup Recovery Point
# =========================================================

def get_latest_backup(ami_id):

    region = boto3.Session().region_name

    account_id = boto3.client(
        "sts"
    ).get_caller_identity()["Account"]

    # -----------------------------------------------------
    # AWS Backup resource ARN for EC2 AMI
    # -----------------------------------------------------

    resource_arn = (
        f"arn:aws:ec2:{region}:"
        f"{account_id}:image/{ami_id}"
    )

    logger.info(
        "Searching AWS Backup recovery points for %s",
        resource_arn
    )

    latest_backup = None

    paginator = backup.get_paginator(
        "list_recovery_points_by_resource"
    )

    try:

        for page in paginator.paginate(
            ResourceArn=resource_arn
        ):

            recovery_points = page.get(
                "RecoveryPoints",
                []
            )

            for recovery_point in recovery_points:

                creation_date = recovery_point.get(
                    "CreationDate"
                )

                if not creation_date:

                    continue

                # -------------------------------------------------
                # Find newest recovery point
                # -------------------------------------------------

                if (
                    latest_backup is None
                    or creation_date >
                    latest_backup["CreationDate"]
                ):

                    latest_backup = recovery_point

    except backup.exceptions.ResourceNotFoundException:

        logger.warning(
            "No AWS Backup resource found for AMI %s",
            ami_id
        )

        return None

    except Exception as e:

        logger.error(
            "AWS Backup lookup failed for AMI %s: %s",
            ami_id,
            str(e)
        )

        return None

    return latest_backup


# =========================================================
# Calculate Backup Age
# =========================================================

def calculate_backup_age(
    recovery_point
):

    creation_date = recovery_point[
        "CreationDate"
    ]

    # -----------------------------------------------------
    # boto3 normally returns timezone-aware datetime
    # -----------------------------------------------------

    if creation_date.tzinfo is None:

        creation_date = creation_date.replace(
            tzinfo=timezone.utc
        )

    now = datetime.now(
        timezone.utc
    )

    age = now - creation_date

    return age.total_seconds() / 86400


# =========================================================
# Resolve + Archive Security Hub Finding
# =========================================================

def resolve_security_hub_finding(
    finding_id,
    product_arn,
    ami_id,
    backup_age_days=None,
    reason=""
):

    logger.info(
        "Resolving and archiving Security Hub finding %s",
        finding_id
    )

    # -----------------------------------------------------
    # Build note
    # -----------------------------------------------------

    if backup_age_days is not None:

        note_text = (
            f"AMI {ami_id} has a recent AWS Backup recovery "
            f"point. Latest backup age is "
            f"{backup_age_days:.2f} days. "
            f"Finding resolved automatically. "
            f"Reason: {reason}"
        )

    else:

        note_text = (
            f"AMI {ami_id}. "
            f"Finding resolved automatically. "
            f"Reason: {reason}"
        )

    try:

        securityhub.batch_update_findings(

            FindingIdentifiers=[
                {
                    "Id": finding_id,
                    "ProductArn": product_arn
                }
            ],

            # -------------------------------------------------
            # RESOLVE the finding
            # -------------------------------------------------

            Workflow={
                "Status": "RESOLVED"
            },

            # -------------------------------------------------
            # ARCHIVE / CLOSE the finding
            # -------------------------------------------------

            RecordState="ARCHIVED",

            # -------------------------------------------------
            # Add note
            # -------------------------------------------------

            Note={
                "Text": note_text,
                "UpdatedBy": "SecurityHubBackupLambda"
            }
        )

        logger.info(
            "Security Hub finding %s resolved and archived successfully",
            finding_id
        )

    except Exception as e:

        logger.error(
            "Failed to resolve/archive Security Hub finding %s: %s",
            finding_id,
            str(e)
        )

        raise
