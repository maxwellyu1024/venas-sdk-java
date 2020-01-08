package com.insight.demo.msgpack.model;

import org.msgpack.annotation.Message;

@Message
public class MessageData {
    public boolean compact;
    public int schema;

    public boolean isCompact() {
        return compact;
    }

    public void setCompact(boolean compact) {
        this.compact = compact;
    }

    public int getSchema() {
        return schema;
    }

    public void setSchema(int schema) {
        this.schema = schema;
    }
}
