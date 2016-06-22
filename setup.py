from setuptools import setup

project_name = 'requests-ntlm2'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

requires = [
    "requests == 2.5.0",
    "ntlmlib >= 0.72"
]

setup(
    name=project_name,
    version=0.01,
    description='Python library to use Requests NTLMv1 or NTLMv2',
    long_description=long_description,
    keywords='requests ntlm ntlmv2 ntlmv1 http'.split(' '),
    author='Ian Clegg',
    author_email='ian.clegg@sourcewarp.com',
    url='https://github.com/ianclegg/',
    license='MIT license',
    packages=['requests_ntlm2'],
    install_requires=requires,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration',
    ],
)
