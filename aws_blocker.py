import boto3

# Configuration for AWS NACL blocking
nacl_id = 'YOUR AWS ACL ID'  # Your Network ACL ID
region = 'YOUR EC2 REGION'  # Use your EC2 region
rule_number_counter = 100  # Starting rule number for deny rules
blocked_ip_rules = {}  # Track IP to rule number mapping for unblocking

def block_ip(ip):
    global rule_number_counter
    print(f"[AWS NACL] Blocking IP {ip} at network level.")
    ec2 = boto3.client('ec2', region_name=region)
    try:
        # Create deny rule for the IP
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number_counter,
            Protocol='-1',  # All protocols
            RuleAction='deny',
            Egress=False,  # Inbound rule
            CidrBlock=f"{ip}/32"
        )
        # Store the mapping for unblocking
        blocked_ip_rules[ip] = rule_number_counter
        print(f"[AWS NACL] Successfully blocked {ip} with rule {rule_number_counter}")
        rule_number_counter += 1  # Increment for next rule
    except Exception as e:
        print(f"[AWS NACL] Error blocking {ip}: {e}")

def unblock_ip(ip):
    print(f"[AWS NACL] Unblocking IP {ip}.")
    ec2 = boto3.client('ec2', region_name=region)
    try:
        # Get the rule number for this IP
        if ip in blocked_ip_rules:
            rule_number = blocked_ip_rules[ip]
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Egress=False
            )
            # Remove from tracking
            del blocked_ip_rules[ip]
            print(f"[AWS NACL] Successfully unblocked {ip} (rule {rule_number})")
        else:
            print(f"[AWS NACL] No rule found for IP {ip}")
    except Exception as e:
        print(f"[AWS NACL] Error unblocking {ip}: {e}")
