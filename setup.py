from setuptools import setup


setup(
    name="ecc_verifiable_threshold_cryptosystem",
    version="0.1",
    packages=['threshold_library'],
    scripts=[
        'threshold.py',
    ],
    install_requires=[
        'ecdsa==0.19.2',
    ],
    test_suite='test',
)
