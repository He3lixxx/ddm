## Basic Algorithm Explanation
This implementation is based on the following algorithmic idea:
- Load as many hashes as every node can hold into the memory
- Distribute all the hashes we are searching for to every worker.
- Evenly split up all hints / passwords that need to be checked and
  distribute them to the workers
- Each worker then checks its assigned range for hash matches.
  If a match is found, the master is notified

This has one main advantage: As long as all hashes we are searching
for can be kept in memory on all workers, we will only need to search
the whole range of possible hints and passwords once and find all solutions.

However, for large input data sets, it might happen that not all hashes can
be kept in memory on each node. In this case, we need to do multiple
iterations. In each iteration, each node only gets a part of the hashes we
are searching for. Thus, we need to cycle through the same hashes multiple
times. This effectively multiplies the time required for the algorithm to
finish by the count of required iterations. Thus, you want to make sure to
prevent multiple iterations as effectively as possible.

We think that this is the only solution to solve the case where the input
is too big to be kept in memory as we're not allowed to use the disk,
and doing multiple iterations where each iteration re-reads the whole file
is effectively using the disk.

#### Preventing multiple iterations
We were not allowed to change the command line interface, so we could not
provide a way to set the handling of iterations there. Thus, we added a
public constant member `MAXIMUM_HASHES_TO_FIT_IN_MEMORY` to the `Master`
Actor
(`ddm/ddm-pc/src/main/java/de/hpi/ddm/actors/Master.java:52`).
Here, you need to set the count of hashes that every System can fit
in its memory. 

**Important**: If the program runs out of memory or an error is shown that multiple
iterations are necessary, please update this value to an appropriate
value for the system you are running on.

For input files that are smaller than the RAM size of the nodes, it
should be possible to prevent multiple iterations, which guarantees
minimal run times.

We're pretty sure that this implementation gives the best possible
performance for any input data that could realistically be encountered,
although you can artifically craft input files that will take longer to
process than actually necessary (e.g. if all possible passwords of the
alphabet are valid). If you encounter any problems or bad performance,
please contact us.