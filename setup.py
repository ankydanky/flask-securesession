"""
Flask-SecureSession
-------------

Flask-Session is an extension for Flask that adds support for
Server-side Session to your application.

"""
from setuptools import setup, find_packages


setup(
    name='Flask-SecureSession',
    version='0.3.3',
    url='https://github.com/ankydanky/flask-securesession',
    license='BSD',
    author='NDK',
    author_email='andy@ndk.sytes.net',
    description='Adds encrypted server-side session support to your Flask application',
    long_description=__doc__,
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask>=1.0',
        'cachelib>=0.1.1',
        'pycryptodome>=3.9.9'
    ],
    test_suite='test_session',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
