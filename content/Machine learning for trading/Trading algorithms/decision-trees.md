---
title: Decision trees
tags:
  - cs7646
  - machine
  - learning
  - trading
  - decision
  - trees
  - numpy
  - entropy
  - correlation
  - gini
  - index
  - random
---

These notes cover the lectures provided in the following Youtube links:

- [Decision Trees 1](https://www.youtube.com/watch?v=OBWL4oLT7Uc)
- [Decision Trees 2](https://www.youtube.com/watch?v=WVc3cjvDHhw)

## Decision Trees Part 1

**Part 1** primarily covers the purpose of decision trees, their structure, how
they're used, how they can be implemented in a NumPy 2D array, and some thoughts
are provided on their performance. In summary, decision trees:

- Have factors with numerical or boolean values
- Each node in the tree is a factor coupled with the split value
- **Split values** decide whether to take the left or right branch
- Leaf nodes are nodes within decisions trees that have no child nodes
- Leaf nodes are considered the **Y** value or **predictive outcome** of a
  machine learning model built with a decision tree
- Decision trees have a performance of log(n) (base 2), with `n` being the
  number of nodes (decisions) in the tree based upon factors provided

## Decision Trees Part 2

To build a decision tree from a 2D NumPy array, we can leverage the following
pseudocode:

```python
def build_tree(data):
    if data.shape[0] == 1:
        return [leaf, data.y, Null, Null]
    if all data.y same:
        return [leaf, data.y, Null, Null]

    else:
        i = best_feature_to_split_on()
        split_val = data[:, i].median()
        left_tree = build_tree(data[data[:, i] <= split_val])
        right_tree = build_tree(data[data[:, i] > split_val])
        root = [i, split_val, 1, left_tree.shape[0] + 1]
        return (append(root, left_tree, right_tree))
```

## How do we determine the best feature to split on?

During this class, and particularly for linear regression algorithms, we'll be
using **correlation** as our metric for best feature to split on. When
determining the best feature, the vernacular used is **information gain**. Some
example **information gain** metrics used for the creation of decision tree are:

- Entropy
- Correlation
- Gini Index

## Building trees faster

Given the algorithm to build a decision tree (above), the slowest portions of
this algorithm are **best_feature_to_split_on()** and taking the median of
`data[:, i]` to find the `split_val`. We can speed up the process of building
our decision tree by leveraging **random trees**, an algorithm to do so is
below:

```python
def build_tree(data):
    if data.shape[0] == 1:
        return [leaf, data.y, Null, Null]
    if all data.y same:
        return [leaf, data.y, Null, Null]

    else:
        i = random_feature_to_split_on()
        split_val = (data[random, i] + data[random, i]) / 2
        left_tree = build_tree(data[data[:, i] <= split_val])
        right_tree = build_tree(data[data[:, i] > split_val])
        root = [i, split_val, 1, left_tree.shape[0] + 1]
        return (append(root, left_tree, right_tree))
```

In the above algorithm, the major changes from the previous decision tree
algorithm is that we select a **random** feature to split on for this particular
node and then we take the average of two values from two **random** rows in the
data.

### Doesn't this randomness effect the predictive performance of my tree?

Yes, however, this can be mitigated by **bagging** or creating an **ensemble**
of models - in this case random decision trees. This is called a **random
forest**.

## Strengths and weaknesses of decision trees

### Strengths

- Cost of query - faster to query than KNN but slower than linear regression
- Don't have to normalize your data

### Weaknesses

- Cost of learning - more expensive than creating a KNN or linear regression
  learner
