## AutoVT - A Virus Total Automation Tool

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

### Results
Scan/Report responses from the server are saved in the results directory of the project.  You can edit the save location by changing the **create_dir()** function in utils.py.

```
utils>utils.py>create_dir()
```

<p align="center">
	<img src="/images/results.png">
</p>

### Usage

```
python autovt.py -h
```

<p align="center">
	<img src="/images/usage.png">
</p>

## Development
This project is still in development, and is currently being worked on.

I would *love* to hear what you think about **AutoVT** on the [issues page](https://github.com/cjcrist/AutoVT/issues). 

Make pull requests, report bugs, suggest ideas, and discuss **AutoVT**.
