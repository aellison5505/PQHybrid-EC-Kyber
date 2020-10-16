npm init
npm install typescript @types/node@^12 typedoc typedoc-plugin-markdown npm-add-script  --save-dev
npm i mocha chai
npx tsc --init --rootDir src --outDir lib --esModuleInterop --sourceMap --target es2015 --declaration --declarationMap --resolveJsonModule --lib es2020,dom  --module commonjs
npx npmAddScript -k "build" -v "tsc"
npx npmAddScript -k "tsc-w" -v "tsc -w"
npx npmAddScript -k "build-docs" -v "touch ./readme.md && rm ./readme.md && npx typedoc --toc --mode modules --theme markdown --out $INIT_CWD/docs --readme $INIT_CWD/readmeHeader/readhead.md $INIT_CWD/src && npx concat-md --decrease-title-levels ./docs > README.md"
mkdir lib
mkdir src
mkdir test
mkdir readmeHeader
touch src/index.ts
touch test/test.js
touch readmeHeader/readhead.md
touch README.md
cat << EOT >> readmeHeader/readhead.md
# ${PWD##*/}
EOT
cat << EOT >> README.md
# ${PWD##*/}
EOT
git init
git commit -m "first commit"
git remote add origin git@github.com:aellison5505/${PWD##*/}.git
git push -u origin master
