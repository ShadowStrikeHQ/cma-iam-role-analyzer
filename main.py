import argparse
import boto3
import logging
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Analyzes IAM roles in AWS to identify potential privilege escalation paths.')
    parser.add_argument('--role-name', help='The name of the IAM role to analyze.')
    parser.add_argument('--profile', help='AWS CLI profile to use for authentication.')
    parser.add_argument('--region', help='AWS region to use. Defaults to configured region or us-east-1.')
    parser.add_argument('--output-file', help='The file to write the analysis results to (JSON format).')
    return parser

def get_role_policies(iam_client, role_name):
    """
    Retrieves inline and attached managed policies for a given IAM role.

    Args:
        iam_client: Boto3 IAM client.
        role_name (str): The name of the IAM role.

    Returns:
        tuple: A tuple containing lists of inline policies and attached managed policies.
    """
    inline_policies = []
    attached_policies = []

    try:
        # Get inline policies
        response = iam_client.get_role(RoleName=role_name)
        inline_policies = response.get('Role', {}).get('RolePolicyList', [])

        # Get attached managed policies
        paginator = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(page['AttachedPolicies'])

        return inline_policies, attached_policies

    except Exception as e:
        logging.error(f"Error retrieving policies for role {role_name}: {e}")
        return [], []

def analyze_policies(inline_policies, attached_policies, iam_client):
    """
    Analyzes the given policies for potential privilege escalation paths.

    Args:
        inline_policies (list): A list of inline policies.
        attached_policies (list): A list of attached managed policies.
        iam_client: Boto3 IAM client

    Returns:
        dict: A dictionary containing the analysis results.
    """
    analysis_results = {
        'inline_policies': [],
        'attached_policies': []
    }

    # Analyze inline policies
    for policy in inline_policies:
        policy_name = policy['PolicyName']
        try:
            policy_document = json.loads(policy['PolicyDocument'])
            analysis_results['inline_policies'].append({
                'policy_name': policy_name,
                'potentially_risky_statements': analyze_policy_document(policy_document)
            })
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding inline policy {policy_name}: {e}")
            analysis_results['inline_policies'].append({
                'policy_name': policy_name,
                'error': f"Failed to decode policy document: {e}"
            })

    # Analyze attached policies
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        policy_name = policy['PolicyName']
        try:
            # Get policy document
            response = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            )
            policy_document = response['PolicyVersion']['Document']
            analysis_results['attached_policies'].append({
                'policy_name': policy_name,
                'policy_arn': policy_arn,
                'potentially_risky_statements': analyze_policy_document(policy_document)
            })
        except Exception as e:
            logging.error(f"Error retrieving or analyzing attached policy {policy_name} ({policy_arn}): {e}")
            analysis_results['attached_policies'].append({
                'policy_name': policy_name,
                'policy_arn': policy_arn,
                'error': f"Failed to retrieve or analyze policy document: {e}"
            })

    return analysis_results

def analyze_policy_document(policy_document):
    """
    Analyzes a single policy document for potentially risky statements.

    Args:
        policy_document (dict): The policy document to analyze.

    Returns:
        list: A list of potentially risky statements.
    """
    risky_statements = []
    for statement in policy_document.get('Statement', []):
        if isinstance(statement, str):
             logging.warning("Invalid statement format. It should be a dict.  Ignoring this statement.")
             continue

        effect = statement.get('Effect', '').lower()
        if effect == 'allow':
            action = statement.get('Action')
            resource = statement.get('Resource')

            if action == '*' or (isinstance(action, list) and '*' in action):
                risky_statements.append({
                    'statement': statement,
                    'reason': 'Wildcard action'
                })
            elif resource == '*' or (isinstance(resource, list) and '*' in resource):
                risky_statements.append({
                    'statement': statement,
                    'reason': 'Wildcard resource'
                })
            elif isinstance(action, list):
                if 'sts:AssumeRole' in [a.lower() for a in action]:
                    risky_statements.append({
                        'statement': statement,
                        'reason': 'sts:AssumeRole permission found.'
                    })

    return risky_statements

def validate_role_name(role_name):
     """
     Validates that the role name is a non-empty string.
     Args:
         role_name: The role name to validate.
     Raises:
         ValueError: If the role name is invalid.
     """
     if not isinstance(role_name, str) or not role_name:
         raise ValueError("Role name must be a non-empty string.")


def main():
    """
    Main function to execute the IAM Role Analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input Validation
    try:
        if args.role_name:
            validate_role_name(args.role_name)
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return

    profile_name = args.profile
    region_name = args.region or os.environ.get('AWS_REGION') or 'us-east-1'  # Default region

    try:
        # Use AWS CLI profile if provided
        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region_name)
            iam_client = session.client('iam')
        else:
            iam_client = boto3.client('iam', region_name=region_name)

        role_name = args.role_name

        # Get role policies
        inline_policies, attached_policies = get_role_policies(iam_client, role_name)

        # Analyze policies
        analysis_results = analyze_policies(inline_policies, attached_policies, iam_client)

        # Output results to file if specified
        if args.output_file:
            try:
                with open(args.output_file, 'w') as f:
                    json.dump(analysis_results, f, indent=4)
                logging.info(f"Analysis results written to {args.output_file}")
            except Exception as e:
                logging.error(f"Error writing results to file: {e}")
        else:
            # Print results to console
            print(json.dumps(analysis_results, indent=4))

    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    # Example usage (from the command line):
    # python cma_iam_role_analyzer.py --role-name MyRole --profile MyProfile --output-file analysis.json
    # python cma_iam_role_analyzer.py --role-name MyRole
    # python cma_iam_role_analyzer.py --role-name MyRole --region us-west-2

    main()