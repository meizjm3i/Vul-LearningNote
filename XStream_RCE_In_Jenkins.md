# Jenkins 2.101 XStream Rce[空指针CTF一月内部赛Writeup]


# 初步分析

在createView中，支持xml格式的数据传入，部分源代码如下：

```java
boolean isXmlSubmission = requestContentType != null && (requestContentType.startsWith("application/xml") || requestContentType.startsWith("text/xml"));
......
if (mode != null && mode.length() != 0) {
    if ("copy".equals(mode)) {
        v = copy(req, owner, name);
    } else {
        ViewDescriptor descriptor = (ViewDescriptor)all().findByName(mode);
        if (descriptor == null) {
            throw new Failure("No view type ‘" + mode + "’ is known");
        }

        v = (View)descriptor.newInstance(req, req.getSubmittedForm());
    }

    owner.getACL().checkCreatePermission(owner, v.getDescriptor());
    v.owner = owner;
    rsp.sendRedirect2(req.getContextPath() + '/' + v.getUrl() + v.getPostConstructLandingPage());
    return v;
} else if (isXmlSubmission) {
    v = createViewFromXML(name, req.getInputStream());
    owner.getACL().checkCreatePermission(owner, v.getDescriptor());
    v.owner = owner;
    rsp.setStatus(200);
    return v;
} else {
    throw new Failure(Messages.View_MissingMode());
}
```

为了进入xml的分支，我们需要将正常createView操作的mode参数去掉，并将Content-Type改为`application/xml`，在createViewFromXML方法中，通过XSteam来进行xml的反序列化。接下来要思考的就是，如何绕过Jenkins的过滤进行RCE。在进行反序列化的时候，会进行黑名单类的校验，这个问题其实就转化成了怎么绕过黑名单进行反序列化。黑名单如下：
```java
private static final String[] DEFAULT_PATTERNS = new String[]{
"^bsh[.].*", 
"^com[.]google[.]inject[.].*", 
"^com[.]mchange[.]v2[.]c3p0[.].*", 
"^com[.]sun[.]jndi[.].*", 
"^com[.]sun[.]corba[.].*", 
"^com[.]sun[.]javafx[.].*", "^com[.]sun[.]org[.]apache[.]regex[.]internal[.].*", 
"^java[.]awt[.].*", 
"^java[.]rmi[.].*", 
"^javax[.]management[.].*", 
"^javax[.]naming[.].*", 
"^javax[.]script[.].*", 
"^javax[.]swing[.].*", 
"^org[.]apache[.]commons[.]beanutils[.].*", "^org[.]apache[.]commons[.]collections[.]functors[.].*", "^org[.]apache[.]myfaces[.].*", 
"^org[.]apache[.]wicket[.].*", 
".*org[.]apache[.]xalan.*", 
"^org[.]codehaus[.]groovy[.]runtime[.].*",
 "^org[.]hibernate[.].*", 
 "^org[.]python[.].*", 
 "^org[.]springframework[.](?!(\\p{Alnum}+[.])*\\p{Alnum}*Exception$).*", "^sun[.]rmi[.].*", 
 "^javax[.]imageio[.].*", 
 "^java[.]util[.]ServiceLoader$", 
 "^java[.]net[.]URLClassLoader$"
 };
```

从漏洞原作者之前发布的分析文章可以发现，他最终找到了`bcelClassLoader + LazyIterator`这样的一个利用思路，接下来我们同样按着他的思路去进行构造。

# 使用BcelClassLoader进行类加载

参考文章：https://paper.seebug.org/572/#0x02-fastjson

ClassLoader会将编码过的evil.class文件转化为bytep[]，再通过defineClass还原出Class，也就是我们自己生成的evil类。进行Class.forName调用时，如果第二个参数`true`的话，就支持类的初始化，而类的初始化会伴随static代码块的执行。在@orich的文章中，他通过`com.sun.xml.internal.ws.util.ServiceFinder$LazyIterator`来进行`XStream`与`Class.forName`的联动:

```java
public T next() {
    if (!this.hasNext()) {
        throw new NoSuchElementException();
    } else {
        ServiceFinder.ServiceName sn = this.names[this.index++];
        String cn = sn.className;
        URL currentConfig = sn.config;
        try {
            return this.service.cast(Class.forName(cn, true, this.loader).newInstance());
        } catch (ClassNotFoundException var5) {
            ServiceFinder.fail(this.service, "Provider " + cn + " is specified in " + currentConfig + " but not found");
        } catch (Exception var6) {
            ServiceFinder.fail(this.service, "Provider " + cn + " is specified in " + currentConfig + "but could not be instantiated: " + var6, var6);
        }
        return null;
    }
}
```

其中`Class.forName`的cn参数是从`this.names`而来，因此可以通过xml来直接控制这两个参数。所以这一部分的调用过程为：

```
1. com.sun.xml.internal.ws.util.ServiceFinder$LazyIterator#next
2. Java.lang.Class#forName
3. com.sun.org.apache.bcel.internal.util.ClassLoader#loadClass
```

# XStream到LazyIterator

观察XStream恢复用到的xml文档，可以发现最外层是一个map标签，在恢复xml结构到对象的过程中，map默认使用的HashMap，在在对后续的标签处理中，会涉及key和value的存储，这时会调用put函数，而put函数中，由于使用的是HashMap，因此会调用哈希计算函数HashCode。

从[https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf](https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf)这篇文章中可以找到前半部分poc构造的一个思路，即:

```
1. jdk.nashorn.internal.objects.NativeString的HashCode函数可以触发Native String->getStringValue()
2. getStringValue() 调用了 java.lang.CharSequence->toString()
3. com.sun.xml.internal.bind.v2.runtime.unmarshaller.
Base64Data 的 toString()方法反射调用Base64Data->get()
4. Base64Data->get() 触发了来自javax.activation.DataSource的java.io.InputStream的read函数，并且com.sun.xml.internal.ws.encoding.xml.
XMLMessage$XmlDataSource是DataSource的一个继承
5. javax.crypto.CipherInputStream 的read()最终会调用 javax.crypto.
Cipher->update()
6. javax.crypto.Cipher->update() 通过 chooseFirstProvider() 来触发一个指定的Iterator
```

从第六步可以发现已经和LazyIterator串起来了，这也是利用链基本完整的流程。

有一个非常有名的XStream反序列化漏洞，那就是Struts2 052，这里主要讲它的poc生成，网上常用的方法是通过marshalsec进行，命令为：

```
java -cp target/marshalsec-0.0.1-SNAPSHOT-all.jar marshalsec.XStream ImageIO "calc" > poc.xml
```
这里就会发现，黑名单中是存在`^javax[.]imageio[.].*`这样一条规则的，因此需要前文所提到的`LazyIterator`来替代，此时整个链已经大致完整。

在LazyIterator中，loader参数就是前文所提到的bcel classloader，而names参数则是`$$BCEL$$`开头的类编码，以及index参数为0，具体构造可以直接看`LazyIterator`的next函数:

```java
public T next() {
    if (!this.hasNext()) {
        throw new NoSuchElementException();
    } else {
        ServiceFinder.ServiceName sn = this.names[this.index++];
        String cn = sn.className;
        URL currentConfig = sn.config;

        try {
            return this.service.cast(Class.forName(cn, true, this.loader).newInstance());
        } catch (ClassNotFoundException var5) {
            ServiceFinder.fail(this.service, "Provider " + cn + " is specified in " + currentConfig + " but not found");
        } catch (Exception var6) {
            ServiceFinder.fail(this.service, "Provider " + cn + " is specified in " + currentConfig + "but could not be instantiated: " + var6, var6);
        }

        return null;
    }
}
```

接下来就是构造`com.sun.org.apache.bcel.internal.util.ClassLoader`。从它的`loadClass`中可以找到`$$BCEL$$`的解析部分，有关于`com.sun.org.apache.bcel.internal.util.ClassLoader`的更细致的参数构造，在`java.lang.ClassLoader`以及它本身的定义代码中已经有了说明，各位可以去自行学习。



# Refererence

- https://www.anquanke.com/post/id/172198#h2-4
- https://paper.seebug.org/572/#0x02-fastjson
- https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf
- https://www.freebuf.com/vuls/97659.html