package com.example.security.services;

public interface TSAClient {
    byte[] getTimeStampResponse(byte[] requestBytes) throws Exception;
}
