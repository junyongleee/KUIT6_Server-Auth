package com.example.kuit.dto.response;

public record ReissueResponse(
        String accessToken,
        String refreshToken
)
{
    public static ReissueResponse of(String accessToken, String refreshToken) {
        return new ReissueResponse(accessToken, refreshToken);
    }
}
