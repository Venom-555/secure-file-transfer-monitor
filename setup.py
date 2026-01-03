from setuptools import setup, find_packages

setup(
    name="secure-file-transfer-monitor",
    version="1.0.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "secure-file-monitor=src.monitor:main"
        ]
    },
    python_requires=">=3.8",
)
