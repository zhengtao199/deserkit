package org.apache.naming;

/** Tomcat ResourceRef 复刻（新版层级：继承 AbstractRef，SUID=1L，无实例字段） */
public class ResourceRef extends AbstractRef {
    private static final long serialVersionUID = 1L;

    public ResourceRef(String resourceClass, String description,
                       String scope, String auth, boolean singleton,
                       String factory, String factoryLocation) {
        super(resourceClass, factory, factoryLocation);
        if (description != null) add(new javax.naming.StringRefAddr("description", description));
        if (scope != null) add(new javax.naming.StringRefAddr("scope", scope));
        if (auth != null) add(new javax.naming.StringRefAddr("auth", auth));
        add(new javax.naming.StringRefAddr("singleton", Boolean.toString(singleton)));
    }
}
