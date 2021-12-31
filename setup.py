import setuptools

from validatedata import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="validatedata",
    version=__version__,
    author="Edward Kigozi",
    author_email='edwardinbytes@gmail.com',
    license='MIT',
    description="An easier way to validate data in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Edward-K1/validatedata",
    install_requires=['python-dateutil'],
    packages=setuptools.find_packages(exclude=['tests', '.github']),
    include_package_data=True,
    keywords = "validate data validation",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',

)