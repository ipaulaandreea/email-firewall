package com.example.emailfirewall.service;

import org.springframework.stereotype.Component;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

@Component
public class DnsTxtResolver {

    public String firstTxt(String name) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(name, new String[]{"TXT"});
            Attribute attr = attrs.get("TXT");
            if (attr == null) return null;

            NamingEnumeration<?> en = attr.getAll();
            if (!en.hasMore()) return null;
            Object v = en.next();
            if (v == null) return null;

            String s = v.toString().replace('"', ' ').trim();
            return s.isBlank() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    public boolean hasTxtStartingWith(String domain, String prefixLowerCase) {
        String txt = firstTxt(domain);
        if (txt == null) return false;
        return txt.toLowerCase().startsWith(prefixLowerCase);
    }
}

