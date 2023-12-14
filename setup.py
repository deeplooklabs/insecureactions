from setuptools import setup, find_packages

setup(
    name='insecureactions',
    version='0.1.0',
    description='Search insecure actions on organizations',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='DeepLook Labs',
    author_email='contact@deeplooklabs',
    url='https://github.com/deeplooklabs/insecureactions',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests',
        'colorama'
    ],
    entry_points={
        'console_scripts': [
            'insecureactions=insecureactions.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
