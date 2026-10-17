package org.apache.naming;

/** Tomcat AbstractRef 复刻（新版层级，SUID=1L，无实例字段） */
public abstract class AbstractRef extends javax.naming.Reference {
    private static final long serialVersionUID = 1L;

    public AbstractRef(String className, String factory, String factoryLocation) {
        super(className, factory, factoryLocation);
    }
}
