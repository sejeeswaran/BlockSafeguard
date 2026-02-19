import boto3
import os
from dotenv import load_dotenv

load_dotenv()

nacl_id = os.environ.get('AWS_NACL_ID')
region = os.environ.get('AWS_REGION')
rule_number_counter = 100
blocked_ip_rules = {}

def block_ip(ip):
    global rule_number_counter
    print(f"[AWS NACL] Blocking IP {ip} at network level.")
    ec2 = boto3.client('ec2', region_name=region)
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number_counter,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f"{ip}/32"
        )
        blocked_ip_rules[ip] = rule_number_counter
        print(f"[AWS NACL] Successfully blocked {ip} with rule {rule_number_counter}")
        rule_number_counter += 1
    except Exception as e:
        print(f"[AWS NACL] Error blocking {ip}: {e}")

def unblock_ip(ip):
    print(f"[AWS NACL] Unblocking IP {ip}.")
    ec2 = boto3.client('ec2', region_name=region)
    try:
        if ip in blocked_ip_rules:
            rule_number = blocked_ip_rules[ip]
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Egress=False
            )
            del blocked_ip_rules[ip]
            print(f"[AWS NACL] Successfully unblocked {ip} (rule {rule_number})")
        else:
            print(f"[AWS NACL] No rule found for IP {ip}")
    except Exception as e:
        print(f"[AWS NACL] Error unblocking {ip}: {e}")
