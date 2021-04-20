import matplotlib.pyplot as plt
import pandas as pd
from sklearn.linear_model import LinearRegression

data = pd.read_csv("stats/time_ClientCP2.csv", sep="\t")
size = data.iloc[:, 0].values.reshape(-1, 1)
time = data.iloc[:, 1].values.reshape(-1, 1)
linear_regressor = LinearRegression()
linear_regressor.fit(size, time)
Y_pred = linear_regressor.predict(size)  # make predictions
print(
    linear_regressor.coef_,
    linear_regressor.intercept_,
    linear_regressor.score(size, time),
)

plt.scatter(size, time)
plt.plot(size, Y_pred, color="red")
plt.xlabel("Filesize (bits)")
plt.ylabel("Time taken (s)")
plt.show()
