## dircrypt

Encrypts & decrypts entire directories, recursively. Blazing fast!

<table>
<tr>
    <td>Before</td>
    <td>After</td>
</tr>
<tr>
    <td>
        <pre>
<span class="file-folder">test</span>
├── <span class="file-txt">1.txt</span>
├── <span class="file-png">test.png</span>
└── <span class="file-folder">xx</span>
    ├── <span class="file-txt">lorem-ipsum.txt</span>
    └── <span class="file-folder">yy</span>
        └── <span class="file-png">a.png</span>
        </pre>
    </td>
    <td>
        <pre>
<span class="file-folder">test</span>
├──  <span class="file-folder">DCDATA</span>
│   ├── <span class="file-unknown">92fb7b0f-...</span>
│   ├── <span class="file-unknown">a3644779-...</span>
│   ├── <span class="file-unknown">d4967095-...</span>
│   └── <span class="file-unknown">fdded5db-...</span>
└──  <span class="file-txt">DCMETA.txt</span>
        </pre>
    </td>
</tr>
</table>

`dircrypt` runs extremely fast regardless of the size or number of files in the directory. It flattens the directory structure, removing suffixes and replacing filenames with UUIDs. This prevents your data from being previewed, searched or accidentally presented, ensuring that your data is private.

## Dependencies

None.

## Usage

```bash
python dircrypt.py --help
```
