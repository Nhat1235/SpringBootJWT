# SpringBootJWT
Demo for spring boot authentication/authorization with basic JWT

#Cài đặt: 
1. application.properties:
+ CSDL: ddl-auto = create -> csdl sẽ tự tạo mới sau mỗi lần chạy
D:\\JWTDemo\\src\\main\\resources\\static\\JWTConfig.txt -> đường dẫn mặc định chứa thông tin cấu hình JWT, có thể thay đổi nếu file nằm chỗ khác

2. JWTConfig.txt: 
+ Phải chứa đầy đủ thông tin sau: 
SECRET_KEY=
ACCESS_TOKEN_TIMEOUT=
REFRESH_TOKEN_TIMEOUT=
