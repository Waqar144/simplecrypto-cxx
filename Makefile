dbg:
	mkdir -p build_deb && cd build_deb && cmake -DCMAKE_BUILD_TYPE=Debug -DSIMPLECRYPTO_ENABLE_BENCH=ON -DSIMPLECRYPTO_ENABLE_TESTS=ON ../ && make -j4

rel:
	mkdir -p build_rel && cd build_rel \
	&& cmake -DCMAKE_BUILD_TYPE=Release -DSIMPLECRYPTO_ENABLE_BENCH=ON -DSIMPLECRYPTO_ENABLE_TESTS=ON ../ \
	&& make -j4

runtest:
	mkdir -p build_deb && cd build_deb && cmake -DCMAKE_BUILD_TYPE=Debug -DSIMPLECRYPTO_ENABLE_TESTS=ON ../ && make -j4 \
	&& ./tests/testmain

bench:
	mkdir -p build_rel && cd build_rel \
	&& cmake -DCMAKE_BUILD_TYPE=Release -DSIMPLECRYPTO_ENABLE_BENCH=ON -DSIMPLECRYPTO_ENABLE_TESTS=ON ../ \
	&& make -j4 \
	&& ./bench \
	&& ./bench_c

