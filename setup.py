import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="validatedata",
    version="0.0.1.4",
    author="Edward Kigozi",
    author_email='edwardinbytes@gmail.com',
    description="Validate data in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Edward-K1/validatedata",
    install_requires=['python-dateutil'],
    packages=setuptools.find_packages(),
    include_package_data=True,
    keywords = "validate data validation",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.3',

)