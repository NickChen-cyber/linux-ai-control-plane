CREATE TABLE IF NOT EXISTS reliability_policy (
  id SMALLINT PRIMARY KEY CHECK(id=1),
  window_days INTEGER NOT NULL CHECK(window_days BETWEEN 7 AND 90),
  availability_target NUMERIC(5,2) NOT NULL CHECK(availability_target BETWEEN 90 AND 100),
  mtta_target_minutes INTEGER NOT NULL CHECK(mtta_target_minutes BETWEEN 1 AND 1440),
  mttr_target_minutes INTEGER NOT NULL CHECK(mttr_target_minutes BETWEEN 1 AND 10080),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
);

INSERT INTO reliability_policy(id,window_days,availability_target,mtta_target_minutes,mttr_target_minutes)
VALUES(1,30,99.50,15,120)
ON CONFLICT(id) DO NOTHING;
