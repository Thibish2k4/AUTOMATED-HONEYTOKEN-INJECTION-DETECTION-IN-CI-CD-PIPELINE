from setuptools import setup, find_packages

setup(
    name="windows-honeytoken-tool",
    version="1.0.0",
    description="Windows-optimized honeytoken CI/CD security tool",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "flask>=2.3.0", 
        "requests>=2.31.0",
        "psutil>=5.9.0",
        "pywin32>=306",
        "win10toast>=0.9",
        "schedule>=1.2.0"
    ],
    entry_points={
        'console_scripts': [
            'honeytoken=src.windows_cli:cli',
        ],
    },
    python_requires=">=3.8",
)
