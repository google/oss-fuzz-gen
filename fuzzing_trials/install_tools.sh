
mkdir tools

pushd tools
git clone https://github.com/ispras/casr 
cd casr
cargo update 
cargo build --release
popd