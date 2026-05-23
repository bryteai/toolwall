"""GPU smoke test --- verifies A10G allocation + CUDA + torch."""

import modal

app = modal.App("toolwall-smoke")

image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "torch==2.4.0", "transformers==4.46.0"
)


@app.function(image=image, gpu="A10G", timeout=120)
def smoke() -> str:
    import platform

    import torch

    lines = [
        f"python              {platform.python_version()}",
        f"torch               {torch.__version__}",
        f"cuda_available      {torch.cuda.is_available()}",
        f"device_count        {torch.cuda.device_count()}",
    ]
    if torch.cuda.is_available():
        cap = torch.cuda.get_device_capability(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
        lines.extend(
            [
                f"device_name         {torch.cuda.get_device_name(0)}",
                f"device_capability   sm_{cap[0]}{cap[1]}",
                f"vram_gb             {vram_gb:.1f}",
            ]
        )
    return "\n".join(lines)


@app.local_entrypoint()
def main() -> None:
    print(smoke.remote())
