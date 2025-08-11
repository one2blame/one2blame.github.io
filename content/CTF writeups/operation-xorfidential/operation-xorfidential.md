# Commands

sudo docker pull public.ecr.aws/t0j9q6v5/dev/xorfidential:latest

sudo docker run --rm --interactive --tty --entrypoint /bin/bash --volume $(pwd):/tmp public.ecr.aws/t0j9q6v5/dev/xorfidential:latest

gcc challenge.c -m32 -fno-stack-protector -no-pie -fcf-protection=none -g -o challenge

aws iam list-user-tags --user-name $AWS_USERNAME

aws iam list-policies --scope AWS                                                                                                                                                                                                                                   254 ↵

An error occurred (AccessDenied) when calling the ListPolicies operation: User: arn:aws:iam::942010117876:user/xorfidential-pwn-challenge-user is not authorized to perform: iam:ListPolicies on resource: policy path / because no identity-based policy allows the iam:ListPolicies action

AWS_USERNAME='xorfidential-pwn-challenge-user'

aws iam list-user-tags --user-name $AWS_USERNAME

{
    "Tags": [
        {
            "Key": "Hint",
            "Value": "The target policy name is a tag on this user."
        },
        {
            "Key": "TargetPolicyName",
            "Value": "xorfidential-flag-policy"
        },
        {
            "Key": "Environment",
            "Value": "prod"
        },
        {
            "Key": "Owner",
            "Value": "g0th3r"
        },
        {
            "Key": "Project",
            "Value": "xorfidential"
        }
    ]
}

aws iam get-policy --policy-arn arn:aws:iam::942010117876:policy/xorfidential-flag-policy

{
    "Policy": {
        "PolicyName": "xorfidential-flag-policy",
        "PolicyId": "ANPA5WVBNV32ELKUVKWIE",
        "Arn": "arn:aws:iam::942010117876:policy/xorfidential-flag-policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "FLAG-{5om3timesy0uh4v370XORtoaccessBDg}",
        "CreateDate": "2025-08-02T19:50:28+00:00",
        "UpdateDate": "2025-08-02T19:50:28+00:00",
        "Tags": [
            {
                "Key": "Project",
                "Value": "xorfidential"
            },
            {
                "Key": "Environment",
                "Value": "prod"
            },
            {
                "Key": "Owner",
                "Value": "g0th3r"
            }
        ]
    }
}

# Tools

