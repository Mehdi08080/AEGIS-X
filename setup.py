from setuptools import find_packages, setup

setup(
    name="aegis-x",
    version="0.1.0",
    description="AEGIS-X Security Intelligence Platform",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.30.0",
        "pydantic>=2.7.0",
        "httpx>=0.27.0",
        "pytest>=8.0.0",
    ],
    python_requires=">=3.11",
)
