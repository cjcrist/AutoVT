## Virus Total Automation

This is a quick and dirty project to automate some tasks with Virus Total's public API, and is being developed on Ubuntu Linux 20.04 using Python 3.8.2.    

Before using this tool, you first need to sign up and acquire an API key from Virus Total. More information on getting an API key, and documents for the Virus Total API can be found [here](https://developers.virustotal.com/reference#getting-started).

Once you have an API key, you can load it into environment variables like this:

```
export VT_API_KEY="Your API KEY"
```

The API key variable is stored in **config/config.py**. If you are using virtualenv, there is an issue where some global environment variables do not load.  I found this to be an issue when launching an editor, like PyCharm.  To get around this, either launch the editor from the terminal, or edit the local environment variables in PyCharm:
	
```
File>Settings>Python Console>Environment Variables. 
```

This project is still in development, and is currently being worked on.  I'm working on the public API only, with plans to work on the private API in the future.  If you would like to add to this project, feel free to fork the project and submit a merge request with updates and features.

#### Usage:
<p align="center">
	<img src="/images/usage.png">
</p>
