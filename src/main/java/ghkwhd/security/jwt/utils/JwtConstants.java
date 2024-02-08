package ghkwhd.security.jwt.utils;

public class JwtConstants {
    public static final String key = "DG3K2NG9lK3T2FLfnO283HO1NFLAy9FGJ23UM9Rv923YRV923HT";
    public static final int ACCESS_EXP_TIME = 10;   // 10분
    public static final int REFRESH_EXP_TIME = 60 * 24;   // 24시간

    public static final String JWT_HEADER = "Authorization";
    public static final String JWT_TYPE = "Bearer ";
}
