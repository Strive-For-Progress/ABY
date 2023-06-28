
add_executable(bid_test bid_test.cpp common/bid.cpp)
target_link_libraries(bid_test ABY::aby ENCRYPTO_utils::encrypto_utils)
