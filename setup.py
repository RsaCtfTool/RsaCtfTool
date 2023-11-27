from setuptools import setup

VERSION = "0.0.01"
BASE_CVS_URL = "https://github.com/RsaCtfTool/RsaCtfTool"

setup(
    name="RsaCtfTool",
    packages=[
        "RsaCtfTool",
    ],
    version=VERSION,
    author="Ganapati",
    author_email="something",
    install_requires=[x.strip() for x in open("requirements.txt").readlines()],
    url=BASE_CVS_URL,
    download_url=f"{BASE_CVS_URL}/tarball/{VERSION}",
    keywords=[],
    scripts=["RsaCtfTool.py"],
    include_package_data=True,
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Operating System :: OS Independent",
        "License :: THE BEER-WARE LICENSE",
        "Topic :: Security :: Cryptography",
    ],
    description="RSA multi attacks tool",
    long_description=open("README.md", "r+").read(),
    long_description_content_type="text/markdown",
)
