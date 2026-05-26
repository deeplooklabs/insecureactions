from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="insecureactions",
    version="0.2.0",
    description="Scan GitHub Actions workflows for common security issues",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DeepLook Labs",
    author_email="contact@deeplooklabs.com",
    url="https://github.com/deeplooklabs/insecureactions",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.28",
        "colorama>=0.4",
    ],
    entry_points={
        "console_scripts": [
            "insecureactions=insecureactions.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
