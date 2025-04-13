# Клонируем репозиторий AFL++
//git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
//
# Сборка с поддержкой QEMU
make all qemu_mode
afl-fuzz -Q -i input -o output -- /path/to/your/target_program

