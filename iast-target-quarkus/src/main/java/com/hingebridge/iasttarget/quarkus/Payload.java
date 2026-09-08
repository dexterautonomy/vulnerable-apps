package com.hingebridge.iasttarget.quarkus;

/**
 * The request body, as a bean rather than a Map.
 *
 * <p>Not a style choice. Jackson binds a {@code Map} through its untyped deserializer, which reads
 * string values straight off the parser and never calls the String deserializer the agent watches -
 * so a Map-bound body is invisible to it. A bean with a String field is both the shape a real
 * {@code @RequestBody} or RESTEasy resource uses and the shape the agent's catalogue describes.
 */
public class Payload {

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
