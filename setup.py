from setuptools import setup, find_packages

setup(
    name="password_extractor",
    version="0.1",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "psutil",
        "pywin32; sys_platform == 'win32'",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "password-extractor=password_extractor.main:main",
        ],
    },
)