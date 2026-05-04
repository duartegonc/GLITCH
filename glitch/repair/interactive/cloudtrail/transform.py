from typing import List
from glitch.repair.interactive.cloudtrail.parser import CloudTrailEvent
from glitch.repair.interactive.system import SystemState, State
UNDEF = "glitch-undef"


class CloudTrailTransform:
    @staticmethod
    def build_system_state(events: List[CloudTrailEvent]) -> SystemState:
        state = SystemState()
        for event in events:
            if event.event_source == "s3.amazonaws.com":
                CloudTrailTransform._handle_s3(event, state)
            elif event.event_source == "ec2.amazonaws.com":
                CloudTrailTransform._handle_ec2(event, state)
            elif event.event_source == "iam.amazonaws.com":
                CloudTrailTransform._handle_iam(event, state)
        return state

    @staticmethod
    def _handle_s3(event: CloudTrailEvent, state: SystemState) -> None:
        params = event.request_parameters
        bucket_name = params.get("bucketName", "")
        if not bucket_name:
            return

        path = f"aws_s3_bucket:{bucket_name}"
        if path not in state.state:
            state.state[path] = State()

        if event.event_name == "CreateBucket":
            state.state[path].attrs["state"] = "present"
            acl = params.get("x-amz-acl", UNDEF)
            state.state[path].attrs["acl"] = acl if acl else UNDEF
        elif event.event_name == "PutBucketAcl":
            acl = params.get("AccessControlPolicy", {}).get("AccessControlList", {}).get("Grant", UNDEF)
            if acl == UNDEF:
                acl = params.get("x-amz-acl", UNDEF)
            state.state[path].attrs["acl"] = acl if acl else UNDEF
        elif event.event_name == "DeleteBucket":
            state.state[path].attrs["state"] = "absent"
            state.state[path].attrs["acl"] = UNDEF

    @staticmethod
    def _handle_ec2(event: CloudTrailEvent, state: SystemState) -> None:
        params = event.request_parameters
        instance_id = params.get("instanceId", "")
        if not instance_id:
            return

        path = f"aws_instance:{instance_id}"
        if path not in state.state:
            state.state[path] = State()

        if event.event_name == "RunInstances":
            state.state[path].attrs["state"] = "present"
            instances = params.get("instancesSet", {}).get("items", [])
            if instances:
                instance_type = instances[0].get("instanceType", UNDEF)
                state.state[path].attrs["instance_type"] = instance_type if instance_type else UNDEF
            placement = params.get("placement", {})
            az = placement.get("availabilityZone", UNDEF)
            state.state[path].attrs["availability_zone"] = az if az else UNDEF
        elif event.event_name == "ModifyInstanceAttribute":
            attr = params.get("attribute", "")
            value = params.get("value", UNDEF)
            if attr == "instanceType" and value:
                state.state[path].attrs["instance_type"] = value
        elif event.event_name == "TerminateInstances":
            state.state[path].attrs["state"] = "absent"

    @staticmethod
    def _handle_iam(event: CloudTrailEvent, state: SystemState) -> None:
        params = event.request_parameters
        role_name = params.get("roleName", "")
        if not role_name:
            return

        path = f"aws_iam_role:{role_name}"
        if path not in state.state:
            state.state[path] = State()

        if event.event_name == "CreateRole":
            state.state[path].attrs["state"] = "present"
            policy = params.get("assumeRolePolicyDocument", UNDEF)
            state.state[path].attrs["assume_role_policy"] = policy if policy else UNDEF
        elif event.event_name == "PutRolePolicy":
            state.state[path].attrs["state"] = "present"
            policy = params.get("policyDocument", UNDEF)
            state.state[path].attrs["assume_role_policy"] = policy if policy else UNDEF
        elif event.event_name == "DeleteRole":
            state.state[path].attrs["state"] = "absent"
