from setuptools import setup, find_packages

setup(
    name="cotc_codec",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
    ],
    description="Encryption/Decryption CODEC utilities for Raptor/Temporal",
    author="Your Name",
    author_email="your@email.com",
)