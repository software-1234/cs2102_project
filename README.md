### Quick Start

1. Initialize and activate a virtualenv:
  ```
  $ virtualenv --no-site-packages env
  $ source env/bin/activate
  ```

2. Install the dependencies:
  ```
  $ pip install -r requirements.txt
  ```

3. Start the postgres server
  ```
  brew services start postgres
  ```

4. Update the config file to point to local postgres server

  ```
  SQLALCHEMY_DATABASE_URI = 'postgres://postgres@127.0.0.1:5432'
  ```  

5. Run the development server:
  ```
  $ python app.py
  ```

6. Navigate to [http://localhost:5000](http://localhost:5000)