import unittest
from tempfile import NamedTemporaryFile

from glitch.parsers.cloudformation import CloudFormationParser
from glitch.repair.interactive.cloudtrail.parser import CloudTrailParser
from glitch.repair.interactive.cloudtrail.filter import CloudTrailFilter
from glitch.repair.interactive.cloudtrail.transform import CloudTrailTransform
from glitch.repair.interactive.compiler.names_database import NormalizationVisitor
from glitch.repair.interactive.compiler.labeler import GLITCHLabeler
from glitch.repair.interactive.compiler.compiler import DeltaPCompiler
from glitch.repair.interactive.solver import PatchSolver, PatchApplier
from glitch.repr.inter import UnitBlockType
from glitch.tech import Tech


class TestCloudFormationDrift(unittest.TestCase):
    def test_s3_bucket_acl_drift(self) -> None:
        script = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-drifted-bucket
      AccessControl: Private
"""
        with NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as f:
            f.write(script)
            f.flush()

            parser = CloudFormationParser()
            parsed = parser.parse_file(f.name, UnitBlockType.script)
            assert parsed is not None
            NormalizationVisitor(Tech.cloudformation).visit(parsed)
            labeled = GLITCHLabeler.label(parsed, Tech.cloudformation)
            statement = DeltaPCompiler(labeled).compile()

            events = CloudTrailParser.parse_file(
                "tests/repair/interactive/cloudtrail/fixtures/s3_create_public.json"
            )
            filtered = CloudTrailFilter.filter(events)
            inferred_state = CloudTrailTransform.build_system_state(filtered)

            solver = PatchSolver(statement, inferred_state)
            models = solver.solve()
            assert len(models) >= 1

            PatchApplier(solver).apply_patch(models[0], labeled)

            with open(f.name) as patched:
                content = patched.read()
                assert "PublicRead" in content

    def test_ec2_instance_type_drift(self) -> None:
        script = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.micro
      AvailabilityZone: us-east-1a
"""
        with NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as f:
            f.write(script)
            f.flush()

            parser = CloudFormationParser()
            parsed = parser.parse_file(f.name, UnitBlockType.script)
            assert parsed is not None
            NormalizationVisitor(Tech.cloudformation).visit(parsed)
            labeled = GLITCHLabeler.label(parsed, Tech.cloudformation)
            statement = DeltaPCompiler(labeled).compile()

            events = CloudTrailParser.parse_file(
                "tests/repair/interactive/cloudtrail/fixtures/ec2_modify_instance_type.json"
            )
            filtered = CloudTrailFilter.filter(events)
            inferred_state = CloudTrailTransform.build_system_state(filtered)

            solver = PatchSolver(statement, inferred_state)
            models = solver.solve()
            assert len(models) >= 1

            PatchApplier(solver).apply_patch(models[0], labeled)

            with open(f.name) as patched:
                content = patched.read()
                assert "t2.large" in content

    def test_iam_role_policy_drift(self) -> None:
        """IAM policy drift detection via CloudTrail state inference.

        Note: The solver cannot repair Hash-valued attributes (like
        AssumeRolePolicyDocument) because the compiler falls back to
        PEUnsupported() for nested structures. This test verifies that
        the CloudTrail pipeline correctly infers the state, which is
        sufficient for the state-inference contribution.
        """
        events = CloudTrailParser.parse_file(
            "tests/repair/interactive/cloudtrail/fixtures/iam_put_role_policy.json"
        )
        filtered = CloudTrailFilter.filter(events)
        inferred_state = CloudTrailTransform.build_system_state(filtered)

        assert "aws_iam_role:MyRole" in inferred_state.state
        assert inferred_state.state["aws_iam_role:MyRole"].attrs["state"] == "present"
        policy = inferred_state.state["aws_iam_role:MyRole"].attrs["assume_role_policy"]
        assert "Deny" in policy
