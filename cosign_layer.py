import os
import urllib.request
import zipfile
import subprocess
import json
from pulumi.dynamic import Resource, ResourceProvider, CreateResult, UpdateResult

class CosignLayerProvider(ResourceProvider):
    def create(self, props):
        os.makedirs("layer/bin", exist_ok=True)
        os.makedirs("layer/.docker", exist_ok=True)
        
        # Download cosign binary
        cosign_url = "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        cosign_path = "layer/bin/cosign"
        urllib.request.urlretrieve(cosign_url, cosign_path)
        os.chmod(cosign_path, 0o755)
        
        # Download ECR credential helper
        ecr_helper_url = "https://amazon-ecr-credential-helper-releases.s3.us-east-2.amazonaws.com/0.9.0/linux-amd64/docker-credential-ecr-login"
        ecr_helper_path = "layer/bin/docker-credential-ecr-login"
        urllib.request.urlretrieve(ecr_helper_url, ecr_helper_path)
        os.chmod(ecr_helper_path, 0o755)
        
        # Create Docker config to use ECR credential helper
        docker_config = {
            "credHelpers": {
                "public.ecr.aws": "ecr-login",
                "*.dkr.ecr.*.amazonaws.com": "ecr-login"
            }
        }
        with open("layer/.docker/config.json", "w") as f:
            json.dump(docker_config, f)
        
        # Strip binaries to reduce size
        subprocess.run(["strip", cosign_path], check=False)
        subprocess.run(["strip", ecr_helper_path], check=False)
        
        # Create zip with compression
        with zipfile.ZipFile("layer.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
            zipf.write(cosign_path, "bin/cosign")
            zipf.write(ecr_helper_path, "bin/docker-credential-ecr-login")
            zipf.write("layer/.docker/config.json", ".docker/config.json")
        
        return CreateResult("cosign-layer-prep", outs={"zip_path": "layer.zip"})
    
    def update(self, id, olds, news):
        return UpdateResult(outs=olds)

class CosignLayer(Resource):
    zip_path: str
    
    def __init__(self, name, opts=None):
        super().__init__(CosignLayerProvider(), name, {"zip_path": ""}, opts)
