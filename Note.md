# Anaconda About
1. 系统里同时有Anaconda和自带的Python时，有时候只想使用其中之一的Python解释器，可以在系统环境变量里更改以上两者的先后顺序，命令行界面里键入python时会根据最先得到的路径执行。
2. 命令与含义

|command|meaning|
|-|-|
|python -V/-version|查看当前环境python版本|
|conda -V/-version|查看当前Anaconda版本|
|conda info --envs|查看已创建的环境|
|conda create -n your_env_name python=...|指定版本下创建环境|
|conda remove -n envname -all|删除指定环境|
|conda activate envname|激活环境并进入|
|conda deactivate|退出|
|conda install packagename|安装包|
|pip install packagename|同上|
|conda list|查看该环境下安装的所有包|
|conda update conda|升级当前版本|


# Jupyter Notebook About
1. help(xxx.xx)------>查看指定对象或方法的帮助文档
2. xxx.xx??---------->查看指定对象或方法的源码


# Numpy About
1. numpy.arange()----->生成等差数组，起始索引，结束索引（不包括），步长，类型。reshape()方法可以对之重塑
2. list[num1:num2:num3]----->列表切片，num3步长为-1时，相当于复制一个反转的列表；步长为负数，并且未指定起始索引时，默认起始索引为-1
3. 列表切片为浅拷贝，赋值符号为深拷贝
4. numpy.random.seed()----->随机数的种子方法，seed不指定值时，每次运行都是不一样的随机数，指定种子值时，只要值没变，随机数就没变
5. 权重矩阵w，行是前一层的神经元数量（或是输入矩阵的列数），列是下一层的神经元数量
6. numpy.mean()------->求取矩阵的平均值，参数axis为0计算没一列的均值，为1计算每一行的均值，不指定计算整个矩阵数值加和的均值
7. 查看某个ufunc类的函数（好像应该都是些数学函数）使用方法时，用类似numpy.info(numpy.sin)的命令


# Class About
1. 类的特殊属性

|property|note|
|-|-|
|__bases__|包含积累的一个元组，类可从这些基类直接继承|
|__dict__|与类的命名空间对应的字典，包含命名空间中的标识符和值|
|__doc__|类的文档化字符串|
|__module__|包含模块（文件）名的一个字符串|
|__name__|包含类名的一个字符串|


# Other About
1. 在github上直接写MD文档，些表格时，整个表格上下都要有空行，表格属性行和值行之间要插入```|-|-|```
2. ```apt-cache search```搜索包，```apt-cache show```显示包


# LaTeX About
1. 有时候源文件中用到的是Adobe字体，会报错提示找不到。更换微软字体应该可以解决问题。我做了如下修改：
```\usepackage {xeCJK}
% \setCJKmainfont[AutoFakeBold=true]{Adobe Song Std}
% \setCJKsansfont{Adobe Heiti Std}
% \setCJKmonofont{Adobe Fangsong Std}
\setCJKmainfont{SimSun}
\setCJKsansfont{SimHei}
\setCJKmonofont{FangSong}
```
尤其在编译deep-learning-chinese仓库下的文件时，选择编译的是dlbook_cn.tex


# Windows System About
1. cmd命令重命名文本文件```ren```
