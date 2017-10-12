# How to Use the mruby Debugger

copyright (c) 2014 Specified Non-Profit Corporation mruby Forum

## 1. Summary

This file documents the mruby debugger ('mrdb') methods.

## 2 Debugging with mrdb

## 2.1 Building mrdb

The trunk of the mruby source tree, with the most recent mrdb, can be checked out with the following command:

```bash
$ git clone https://github.com/mruby/mruby.git
```

To run the `make` command:

```bash
$ cd mruby
$ make
```

By default, the `make` command will install the debugger files into mruby/bin.

You can add the path for mrdb on your host environment with the following command:

```bash
$ echo "export PATH=\$PATH:MRUBY_ROOT/bin" >> ~/.bashrc
$ source ~/.bashrc
```

`*MRUBY_ROOT` is the directory in which mruby source code will be installed.

To confirm mrdb was installed properly, run mrdb with the `--version` option:

```bash
$ mrdb --version
mruby 1.3.0 (2017-7-4)
```

## 2.2 Basic Operation

### 2.2.1 Debugging mruby Script Files (rb file) with mrdb

To invoke the mruby debugger, just type `mrdb`.

To specify the script file:

```bash
$ mrdb [option] file name
```

For example: Debugging sample.rb

```bash
$ mrdb sample.rb
```

You can execute the shell commands listed below:

|command|description|
|:-:|:--|
|run|execute programs|
|step|execute stepping|
|continue|execute continuing program|
|break|configure the breaking point|
|delete|deleting the breaking points|
|disable|disabling the breaking points|
|enable|enabling the breaking points|
|info breakpoints|showing list of the breaking points|
|print|evaluating and printing the values of the mruby expressions in the script|
|list|displaying the source cords|
|help|showing help|
|quit|terminating the mruby debugger|

### 2.2.2 Debugging mruby Binary Files (mrb file) with mrdb

You can debug the mruby binary files.

#### 2.2.2.1 Debugging the binary files

* notice
To debug mruby binary files, you need to compile mruby files with option `-g`.

```bash
$ mrbc -g sample.rb
```

You can debug the mruby binary files with following command and the option `-b`.

```bash
$ mrdb -b sample.mrb
```

Then you can execute all debugger shell commands.

#### Break Command

You can use any breakpoint to stop the program by specifying the line number and method name.
The breakpoint list will be displayed after you have set the breakpoint successfully.

Usage:

```
break [file:]linenum
b [file:]linenum
break [class:]method
b [class:]method
```

The breakpoint will be ordered in serial from 1.
The number, which was given to the deleted breakpoint, will never be given to another breakpoint again.

You can give multiple breakpoints to specified the line number and method.
Be ware that breakpoint command will not check the validity of the class name and method name.

You can get the current breakpoint information by the following options.

breakpoint breakpoint number : file name. line number

breakpoint breakpoint number : [class name,] method name

#### Continue Command

Usage:

```
continue [N]
c [N]
```

N: the next breakpoint number

When resuming the program, it will stop at breakpoint N (N-1 breakpoint will be ignored).

When you run the `continue` command without specifying N, the program will be stopped at the next breakpoint.

Example:

```
(foo.rb:1) continue 3
```

This will resume the program and stop it at the third breakpoint.

#### Delete Command

This will delete the specified breakpoint.

Usage:

```
delete [breakpoint-no]
d [breakpoint-no]
```

breakpoint-no: breakpoint number

Example:

```
(foo.rb:1) delete
```

This will delete all of the breakpoints.

```
(foo.rb:1) delete 1 3
```

This will delete the breakpoint at 1 and 3.

#### Disable Command

This will disable the specified breakpoint.

Usage:

```
disable [breakpoint-no]
dis [breakpoint-no]
```

reappointing: breakpoint number

Example:

```
(foo.rb:1) disable
```

Use `disable` if you would like to disable all of the breakpoints.

```
(foo.rb:1) disable 1 3
```

This will disable the breakpoints at 1 and 3.

#### Enable Command

This will enable the specified breakpoints.

Usage:

```
enable [breakpoint-no]
e [breakpoint-no]
```

breakpoint-no: breakpoint number

Example:

```
(foo.rb:1) enable
```

Enabling all breakpoints
```
(foo.rb:1) enable 1 3
```

Enabling the breakpoint 1 and 3

#### eval command

Evaluating the string as source code and printing the value.

Same as print command, please see print command.

#### help command

Displaying the help message.

Usage:

```
help [command]
h [command]
```

Typing `help` without any options will display the command list.

#### Info Breakpoints Command

Displaying the specified breakpoint information.

Usage:

```
info breakpoints [breakpoint-no]
i b [breakpoint-no]
```

breakpoint-no: breakpoint number

Typing "info breakpoints" without ant option will display all breakpoint information.
Example:

```
(sample.rb:1) info breakpoints
Num     Type           Enb What  
1       breakpoint     y   at sample.rb:3                      -> file name,line number
2       breakpoint     n   in Sample_class:sample_class_method -> [class:]method name
3       breakpoint     y   in sample_global_method
```

Displaying the specified breakpoint number:

```
(foo.rb:1) info breakpoints 1 3
Num     Type           Enb What  
1       breakpoint     y   at sample.rb:3  
3       breakpoint     y   in sample_global_method
```

#### List Command

To display the code of the source file.

Usage:

```
list [filename:]first[,last]
l [filename]:first[,last]
```

first: the opening row number
last : the closing row number

When you specify the `first`, but not the `last` option, you will receive 10 rows.
When you do not specify both the `first` and `last` options, you will receive the next 10 rows.

Example:

```
Specifying file name and first row number
sample.rb:1) list sample2.rb:5
```

Specifying the file name and the first and last row number:

```
(sample.rb:1) list sample2.rb:6,7
```

#### Print Command

Evaluating the string as source code and printing the value.

Usage:

```
print [expr]
p [expr]
```

expr: expression

The expression is mandatory.
The displayed expressions will be serially ordered from 1.
If an exception occurs, the exception information will be displayed and the debugging will be continued.

Example:

```
(sample.rb:1) print 1+2
$1 = 3
(sample.rb:1) print self
$2 = main
```

Below is the case of the exception:

```
(sample.rb:1) print (1+2
$1 =  SyntaxError: line 1: syntax error, unexpected $end, expecting ')'
```

#### Quit Command

Quitting the debugger.

Usage:

```
quit
q
```

#### Run Command

Running the program and stopping at the first breakpoint.

Usage:

```
run
r
```

#### Step Command

This will run the program step by step.
When the method and the block are invoked, the program will be stop at the first row.
The program, which is developed in C, will be ignored.
