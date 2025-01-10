# HybridMon prototype implementation

## Description 

This repository contains the code of our HybridMon prototype.

If you use any portion of our work, please cite our paper:

```bibtex
@inproceedings{2025_fink_hybridmon,
    author = {Fink, Ina Berenice and Kunze, Ike and Hein, Pascal and Pennekamp, Jan and Standaert, Benjamin and Wehrle, Klaus and R{\"u}th, Jan},
    title = {{Advancing Network Monitoring with Packet-Level Records and Selective Flow Aggregation}},
    booktitle = {Proceedings of the 2025 IEEE/IFIP Network Operations and Management Symposium (NOMS '25), May 12-16, 2025, Honolulu, HI, USA},
    year = {2025},
    publisher = {IEEE},
}
```
## Execution

1. Configure bfrt_setup.py according to your setup, i.e., sending and collecting machines/interfaces (see dummy entries for src and dst)
2. run bfrt_setup.py
3. run run_pd_rpc.py

## Remark on our use of PRECISION

HybridMon implements PRECISION for subsampling as proposed by Ben Basat et al.:

```bibtex
@article{basat2020precision,
    title={Designing Heavy-Hitter Detection Algorithms for Programmable Switches},
    author={Basat, Ran Ben and Chen, Xiaoqi and Einziger, Gil and Rottenstreich, Ori},
    journal={IEEE/ACM Transactions on Networking},
    volume={28},
    number={3},
    year={2020},
    publisher={IEEE}
}
```

At the time of implementing HybridMon, no Tofino implementation of PRECISION has been available.
It was only released after.
As a result, the parts of our source code concerning subsampling are based on the ideas from the paper above, but have been independently implemented with our own research goals in mind.
To conclude, our implementation does not use any code fragments of PRECISION's original implementation.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.