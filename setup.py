from setuptools import setup, find_packages

VERSION = "0.1.0"
BASE_CVS_URL = "https://github.com/RsaCtfTool/RsaCtfTool"

setup(
    name="RsaCtfTool",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "RsaCtfTool": ["data/*"],  # Include all files inside RsaCtfTool/data/
    },
    version=VERSION,
    author="Ganapati", # Original author
    author_email="something",
    install_requires=[x.strip() for x in open("requirements.txt").readlines()],
    url=BASE_CVS_URL,
    download_url=f"{BASE_CVS_URL}/tarball/{VERSION}",
    entry_points={
        'console_scripts': [
            'rsacrack = RsaCtfTool.main:main',
            'RsaCtfTool = RsaCtfTool.main:main',
        ],
    },
    include_package_data=True,
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    description="RSA multi attacks tool",
    long_description=open("README.md", "r+").read(),
    long_description_content_type="text/markdown",
)
