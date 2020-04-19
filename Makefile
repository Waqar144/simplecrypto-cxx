dbg:
	mkdir -p build_deb && cd build_deb && cmake -DCMAKE_BUILD_TYPE=Debug ../ && make -j4

rel:
	mkdir -p build_rel && cd build_rel \
	&& cmake -DCMAKE_BUILD_TYPE=Release ../ \
	&& make -j4

runtest:
	mkdir -p build_deb && cd build_deb && cmake -DCMAKE_BUILD_TYPE=Debug ../ && make -j4 \
	&& ./tests/testmain

bench:
	mkdir -p build_rel && cd build_rel \
	&& cmake -DCMAKE_BUILD_TYPE=Release ../ \
	&& make -j4 \
	&& ./bench \
	&& ./bench_c

