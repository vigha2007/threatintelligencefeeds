import pandas as pd
for f in ['malicious_ips.csv', 'email_scams.csv']:
    path = 'ML/data/' + f
    df = pd.read_csv(path)
    print(f'--- {f} ---')
    print(f'  Rows: {len(df)}')
    print(f'  Label dist: {dict(df.label.value_counts())}')
    print(f'  Sources: {dict(df.source.value_counts().head(3))}')
    if 'ip' in f:
        print(f'  Sample content: {df.content.head(3).tolist()}')
    else:
        print(f'  Sample content: {str(df.content.head(1).values[0])[:100]}')
